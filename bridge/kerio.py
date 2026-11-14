"""Small, validated subset of the Kerio Control Administration JSON-RPC API."""
import copy
import http.client
import ipaddress
import json
import logging
import ssl
import threading
import time
from contextlib import contextmanager
from http.cookies import SimpleCookie

LOG = logging.getLogger(__name__)


class KerioError(RuntimeError):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def normalized_user(name, default_domain=''):
    name = name.strip()
    if '\\' in name:
        domain, name = name.split('\\', 1)
        name += '@' + domain
    elif '@' not in name and default_domain:
        name += '@' + default_domain
    return name.casefold()


class KerioClient:
    page_size = 500
    max_items = 50000

    def __init__(self, cfg):
        self.cfg = copy.deepcopy(cfg)
        self._lock = threading.RLock()
        self._depth = 0
        self._deadline = 0.
        self._id = 0
        self._token = None
        self._cookies = {}
        self._ctx = ssl.create_default_context(cafile=cfg.get('ca_file') or None)
        if cfg.get('verify', True) is False:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        self._hosts = None
        self._hosts_at = 0.

    @property
    def url(self):
        host = self.cfg['host']
        if ':' in host:
            host = '[' + host.strip('[]') + ']'
        return f"https://{host}:{self.cfg.get('port', 4081)}/admin/api/jsonrpc/"

    def user_name(self, name):
        result = f"{self.cfg.get('prefix', '')}{name}{self.cfg.get('suffix', '')}"
        return normalized_user(result, self.cfg.get('default_domain', ''))

    def matches(self, host, username):
        ref = host.get('user') or {}
        if ref.get('isGroup') or not ref.get('name'):
            return False
        actual = normalized_user(ref['name'], ref.get('domainName', ''))
        expected = normalized_user(username, self.cfg.get('default_domain', ''))
        return actual == expected

    @contextmanager
    def transaction(self):
        if not self._lock.acquire(timeout=10):
            raise KerioError('Kerio busy; retry pending')
        try:
            if self._depth == 0:
                self._deadline = time.monotonic() + 20
            self._depth += 1
            try:
                yield self
            finally:
                self._depth -= 1
        finally:
            self._lock.release()

    def _exchange(self, payload, headers):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise KerioError('Kerio operation deadline exceeded')
        conn = http.client.HTTPSConnection(self.cfg['host'].strip('[]'),
                                          self.cfg.get('port', 4081),
                                          timeout=min(5., remaining), context=self._ctx)
        try:
            conn.request('POST', '/admin/api/jsonrpc/', json.dumps(payload).encode(), headers)
            resp = conn.getresponse()
            if resp.status != 200:
                raise KerioError(f'Kerio HTTP status {resp.status}')
            for name, value in resp.getheaders():
                if name.lower() == 'set-cookie':
                    cookie = SimpleCookie(); cookie.load(value)
                    self._cookies.update({k: v.value for k, v in cookie.items()})
            body = resp.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise KerioError('Kerio response exceeds limit')
            return json.loads(body)
        except (OSError, http.client.HTTPException, ValueError) as ex:
            # Avoid leaking response bodies, tokens, credentials, or internal URLs.
            raise KerioError(f'Kerio transport failure ({type(ex).__name__})') from ex
        finally:
            conn.close()

    def _raw(self, method, params, auth=True):
        self._id += 1
        payload = {'jsonrpc':'2.0', 'id':self._id, 'method':method, 'params':params}
        headers = {'Content-Type':'application/json'}
        if auth:
            headers['X-Token'] = self._token
            if self._cookies:
                headers['Cookie'] = '; '.join(f'{k}={v}' for k,v in self._cookies.items())
        body = self._exchange(payload, headers)
        if not isinstance(body, dict) or body.get('id') != payload['id']:
            raise KerioError('Invalid Kerio response envelope')
        if body.get('error'):
            err = body['error']
            code = err.get('code') if isinstance(err, dict) else None
            raise KerioError(f'Kerio {method} rejected request (code {code})', code)
        if 'result' not in body or not isinstance(body['result'], dict):
            raise KerioError('Kerio response missing result object')
        result = body['result']
        if result.get('errors') or result.get('warnings'):
            raise KerioError(f'Kerio {method} returned item errors or warnings')
        return result

    def _login(self):
        self._token = None
        self._cookies.clear()
        result = self._raw('Session.login', {
            'userName':self.cfg['user'], 'password':self.cfg['password'],
            'application':{'name':'pf-kerio-sso-bridge','vendor':'custom','version':'3.0'}}, False)
        token = result.get('token')
        if not isinstance(token, str) or not token:
            raise KerioError('Kerio login did not return a token')
        self._token = token

    def call(self, method, params):
        with self.transaction():
            if not self._token:
                self._login()
            try:
                return self._raw(method, params)
            except KerioError as ex:
                if ex.code != -32001:
                    raise
                self._login()
                return self._raw(method, params)

    def _list(self, method, **params):
        rows = []
        for start in range(0, self.max_items, self.page_size):
            q = {'fields':[], 'conditions':[], 'combining':'And',
                 'start':start, 'limit':self.page_size, 'orderBy':[]}
            arguments = {**params, 'query':q}
            if method == 'ActiveHosts.get':
                arguments['refresh'] = start == 0
            result = self.call(method, arguments)
            page, total = result.get('list'), result.get('totalItems')
            if not isinstance(page, list) or type(total) is not int or total < 0:
                raise KerioError(f'Invalid {method} list response')
            if total > self.max_items or any(not isinstance(x, dict) for x in page):
                raise KerioError(f'{method} exceeds supported list bounds')
            rows.extend(page)
            if len(rows) >= total:
                return rows
            if not page:
                raise KerioError(f'Incomplete {method} page')
        raise KerioError(f'{method} pagination limit reached')

    def host_by_ip(self, ip, fresh=False):
        addr = ipaddress.ip_address(ip)
        with self.transaction():
            if fresh or self._hosts is None or time.monotonic() - self._hosts_at >= 2:
                self._hosts = self._list('ActiveHosts.get')
                self._hosts_at = time.monotonic()
            found = []
            for host in self._hosts:
                addresses = [host.get('ip')] + (host.get('ip6Addresses') or [])
                for value in addresses:
                    try:
                        matches = ipaddress.ip_address(value) == addr
                    except ValueError:
                        continue
                    if matches:
                        found.append(host)
                        break
            if len(found) > 1:
                raise KerioError('Ambiguous active host IP')
            return copy.deepcopy(found[0]) if found else None

    def logout(self, host_id):
        if not isinstance(host_id, str) or not host_id:
            raise ValueError('A nonempty host ID is required')
        self._hosts = None
        self.call('ActiveHosts.logout', {'ids':[host_id]})

    def login_user(self, host_id, user):
        if not host_id or not user:
            raise ValueError('Host and username are required')
        self._hosts = None
        self.call('ActiveHosts.login', {'hostId':host_id, 'userName':user})

    def test(self):
        with self.transaction():
            self._hosts = None
            return len(self._list('ActiveHosts.get'))
