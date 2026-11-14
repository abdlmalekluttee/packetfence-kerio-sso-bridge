"""Small, validated subset of the Kerio Control Administration JSON-RPC API."""
import copy
import http.client
import ipaddress
import json
import logging
import socket
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

    def __init__(self, cfg, clock=time.monotonic):
        self.cfg = copy.deepcopy(cfg)
        self.clock = clock
        self._unavailable_until = 0.
        self._failures = 0
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
                self._deadline = self.clock() + 20
            self._depth += 1
            try:
                yield self
            finally:
                self._depth -= 1
        finally:
            self._lock.release()

    def _exchange(self, payload, headers):
        remaining = self._deadline - self.clock()
        if remaining <= 0:
            raise KerioError('Kerio operation deadline exceeded')
        conn = http.client.HTTPSConnection(self.cfg['host'].strip('[]'),
                                          self.cfg.get('port', 4081),
                                          timeout=min(5., remaining), context=self._ctx)
        connected = [None]
        def abort():
            transport = connected[0] or conn.sock
            if transport:
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                transport.close()
        deadline = threading.Timer(remaining, abort)
        deadline.daemon = True; deadline.start()
        try:
            conn.request('POST', '/admin/api/jsonrpc/', json.dumps(payload).encode(), headers)
            connected[0] = conn.sock
            resp = conn.getresponse()
            if resp.status != 200:
                raise KerioError(f'Kerio HTTP status {resp.status}')
            for name, value in resp.getheaders():
                if name.lower() == 'set-cookie':
                    cookie = SimpleCookie(); cookie.load(value)
                    self._cookies.update({k: v.value for k, v in cookie.items()})
            chunks = []
            size = 0
            while True:
                remaining = self._deadline - self.clock()
                if remaining <= 0:
                    raise KerioError('Kerio response deadline exceeded')
                if conn.sock:
                    conn.sock.settimeout(min(5., remaining))
                chunk = resp.read1(min(65536, 4 * 1024 * 1024 + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk); size += len(chunk)
                if size > 4 * 1024 * 1024:
                    raise KerioError('Kerio response exceeds limit')
            return json.loads(b''.join(chunks))
        except (OSError, http.client.HTTPException, ValueError) as ex:
            # Avoid leaking response bodies, tokens, credentials, or internal URLs.
            raise KerioError(f'Kerio transport failure ({type(ex).__name__})') from ex
        finally:
            deadline.cancel()
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
        warnings = result.get('warnings')
        # Users.get documents 8003 for local/domain short-name collisions.
        # Domain-scoped lookup and unique full-identity checks remain mandatory.
        # Authentication failures (8004), unknown warnings, and writes fail closed.
        name_collision_only = (method == 'Users.get' and isinstance(warnings, list)
                               and all(isinstance(w, dict) and w.get('code') == 8003
                                       for w in warnings))
        if result.get('errors') or (warnings and not name_collision_only):
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
            if self.clock() < self._unavailable_until:
                raise KerioError('Kerio target in failure backoff; retry pending')
            try:
                if not self._token:
                    self._login()
                try:
                    result = self._raw(method, params)
                except KerioError as ex:
                    if ex.code != -32001:
                        raise
                    self._login()
                    result = self._raw(method, params)
                self._failures = 0
                self._unavailable_until = 0
                return result
            except KerioError as ex:
                self._failures += 1
                self._unavailable_until = self.clock() + min(300, 2 ** min(self._failures, 9))
                raise

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
            if fresh or self._hosts is None or self.clock() - self._hosts_at >= 2:
                self._hosts = self._list('ActiveHosts.get')
                self._host_index = {}
                for host in self._hosts:
                    addresses = set()
                    for value in [host.get('ip')] + (host.get('ip6Addresses') or []):
                        try:
                            addresses.add(ipaddress.ip_address(value))
                        except ValueError:
                            continue
                    for address in addresses:
                        self._host_index.setdefault(address, []).append(host)
                self._hosts_at = self.clock()
            found = self._host_index.get(addr, [])
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

    def _domains(self):
        result = [('local', '')]
        for domain in self._list('Domains.get'):
            did = domain.get('id')
            if did and did != 'local':
                name = (domain.get('service') or {}).get('domainName', '')
                if name:
                    result.append((did, name.casefold()))
        return result

    def resolve_user(self, username):
        """Resolve an exact identity; no fuzzy/short-name cross-domain fallback."""
        expected = normalized_user(username, self.cfg.get('default_domain', ''))
        name, _, domain = expected.partition('@')
        matches = []
        for did, dname in self._domains():
            if domain != dname:
                continue
            for user in self._list('Users.get', domainId=did):
                login = (user.get('credentials') or {}).get('userName', '')
                if normalized_user(login, dname) == expected and user.get('id'):
                    matches.append((did, user))
        if len(matches) != 1:
            raise KerioError('Expected user not uniquely resolved; check username/domain')
        return matches[0]

    def _owner(self, ref):
        domain_name = (ref.get('domainName') or '').casefold()
        if domain_name == 'local':
            domain_name = ''
        for did, name in self._domains():
            if name == domain_name:
                return did, self._user_by_id(did, ref.get('id'))
        raise KerioError('Current host user domain cannot be resolved')

    def _user_by_id(self, domain, uid):
        if not uid:
            raise KerioError('Current host user has no ID')
        users = [u for u in self._list('Users.get', domainId=domain) if u.get('id') == uid]
        if len(users) != 1:
            raise KerioError('Current host user cannot be uniquely resolved')
        return users[0]

    def prepare_conflict(self, host, ip, username):
        """Validate destination, optionally remove only an exact old-owner IP rule.

        This is a configuration operation, not an ActiveHosts logout. Kerio's
        Users.set has no revision compare-and-swap; a last-moment concurrent
        administrator edit cannot be fully excluded. Dedicated API account only.
        """
        with self.transaction():
            if self.matches(host, username):
                return
            automatic = host.get('authMethod') == 'AuthMethodAutomatic'
            override = self.cfg.get('override_manual', False)
            if automatic and not override:
                raise KerioError('Manual automatic-login conflict; override is disabled')
            self.resolve_user(username)  # never tear down a valid login for an unknown user
            ref = host.get('user') or {}
            if not ref.get('name') or (not automatic and not override):
                return
            did, owner = self._owner(ref)
            auto = owner.get('autoLogin') or {}
            addresses = auto.get('addresses') or {}
            values = addresses.get('value')
            if not isinstance(values, list):
                raise KerioError('Unsupported automatic-login address schema')
            exact = []
            for value in values:
                try:
                    if ipaddress.ip_address(value) == ipaddress.ip_address(ip):
                        exact.append(value)
                except ValueError:
                    continue
            if not addresses.get('enabled') or not exact:
                if automatic:
                    raise KerioError('Automatic login uses a rule other than an exact IP; resolve manually')
                return
            if not override:
                raise KerioError('Manual IP conflict; override is disabled')
            if (owner.get('useTemplate') or (auto.get('macAddresses') or {}).get('enabled')
                    or (auto.get('addressGroup') or {}).get('enabled')):
                raise KerioError('Shared MAC/group/template automatic-login rules require manual resolution')
            latest = self._user_by_id(did, owner['id'])
            if latest.get('autoLogin') != auto or latest.get('useTemplate') != owner.get('useTemplate'):
                raise KerioError('Kerio user configuration changed; retry safely')
            updated = copy.deepcopy(auto)
            remaining = [value for value in values if value not in exact]
            updated['addresses'] = {'enabled':bool(remaining), 'value':remaining}
            self.call('Users.set', {'domainId':did, 'userIds':[owner['id']],
                                   'details':{'autoLogin':updated}})
            saved = self._user_by_id(did, owner['id'])
            if saved.get('autoLogin') != updated:
                raise KerioError('Manual IP removal verification failed')
            LOG.warning('manual_ip_removed target=%s user_id=%s ip=%s',
                        self.cfg.get('id'), owner['id'], ip)
