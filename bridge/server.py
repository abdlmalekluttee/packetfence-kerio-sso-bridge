"""Bounded HTTPS transport and management boundary; no import-time side effects."""
import base64
import hmac
import json
import logging
import os
import secrets
import signal
import socket
import ssl
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .engine import Engine
from .registry import Registry
from .state import StateStore

LOG = logging.getLogger(__name__)


@dataclass
class Settings:
    bridge_user: str = ''
    bridge_pass: str = ''
    admin_user: str = ''
    admin_pass: str = ''
    cert_file: str = ''
    key_file: str = ''
    allow_http: bool = False
    public_origin: str = ''
    max_workers: int = 32
    io_timeout: float = 5

    def validate(self):
        for name in ('bridge_user','bridge_pass','admin_user','admin_pass'):
            value = getattr(self, name)
            if not value or value in ('change-me','change-me-too') or any(ord(c)<32 for c in value):
                raise ValueError(f'{name} must be configured without placeholder credentials')
            if name.endswith('user') and ':' in value:
                raise ValueError('Basic-auth usernames cannot contain colons')
        if bool(self.cert_file) != bool(self.key_file):
            raise ValueError('Both CERT_FILE and KEY_FILE must be provided')
        if not self.cert_file and not self.allow_http:
            raise ValueError('TLS required; use ALLOW_HTTP=true only behind a private TLS proxy')
        if not 1 <= self.max_workers <= 128 or not 0.1 <= self.io_timeout <= 30:
            raise ValueError('Invalid HTTP resource limits')
        if self.public_origin and not self.public_origin.startswith('https://'):
            raise ValueError('PUBLIC_ORIGIN must be an HTTPS origin')


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = True

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        # The accept loop handles raw TCP only. A silent TLS peer occupies at most
        # one bounded worker and is closed by a wall-clock request deadline.
        timer = None
        try:
            request.settimeout(self.settings.io_timeout)
            if self.tls_context:
                request = self.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
            def expire():
                try:
                    request.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                request.close()
            timer = threading.Timer(40, expire); timer.daemon = True; timer.start()
            if self.tls_context:
                request.do_handshake()
            super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            request.close()
        finally:
            if timer:
                timer.cancel()
            self.slots.release()

    def handle_error(self, request, client_address):
        LOG.warning('http_request_failed')


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'SSOBridge'

    def _auth(self, admin=False):
        s = self.server.settings
        user, password = (s.admin_user,s.admin_pass) if admin else (s.bridge_user,s.bridge_pass)
        expected = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()
        actual = self.headers.get('Authorization','')
        return hmac.compare_digest(actual.encode(), expected.encode())

    def _send(self, data, code=200, content_type='application/json'):
        if content_type == 'application/json':
            data = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection','close')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        if code == 401:
            self.send_header('WWW-Authenticate','Basic realm="SSO Bridge"')
        self.end_headers()
        self.close_connection = True
        self.wfile.write(data)

    def _body(self):
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('Transfer-Encoding unsupported')
        lengths = self.headers.get_all('Content-Length') or []
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise ValueError('One valid Content-Length is required')
        length = int(lengths[0])
        if length > 65536:
            raise OverflowError('Body too large')
        raw = self.rfile.read(length)
        if self.headers.get_content_type() != 'application/json':
            raise TypeError('Content-Type must be application/json')
        return json.loads(raw)

    def do_GET(self):
        if self.path == '/healthz':
            try:
                status = self.server.engine.status()
                healthy = not status['worker_error']
                return self._send({'ok':healthy}, 200 if healthy else 503)
            except Exception:
                return self._send({'ok':False},503)
        if not self._auth(admin=True):
            return self._send({'error':'Authentication required'},401)
        if self.path in ('/','/ui'):
            return self._send(Path(__file__).with_name('ui.html').read_bytes(),content_type='text/html; charset=utf-8')
        if self.path in ('/ui.js','/ui.css'):
            mime = 'text/javascript; charset=utf-8' if self.path.endswith('.js') else 'text/css; charset=utf-8'
            return self._send(Path(__file__).with_name(self.path[1:]).read_bytes(),content_type=mime)
        if self.path == '/api/session':
            return self._send({'csrf':self.server.csrf})
        if self.path == '/api/kerios':
            return self._send(self.server.registry.public_list())
        if self.path == '/api/status':
            return self._send(self.server.engine.status())
        self._send({'error':'Not found'},404)

    def do_POST(self):
        admin = self.path != '/'
        if not self._auth(admin):
            return self._send({'error':'Authentication required'},401)
        if admin:
            origin = self.server.settings.public_origin or (
                ('https' if self.server.tls_context else 'http') + '://' + self.headers.get('Host',''))
            if (self.headers.get('Origin') != origin or not hmac.compare_digest(
                    self.headers.get('X-CSRF-Token','').encode(), self.server.csrf.encode())):
                return self._send({'error':'Invalid origin or CSRF token'},403)
        try:
            body = self._body()
        except OverflowError:
            return self._send({'error':'Body exceeds 65536 bytes'},413)
        except TypeError:
            return self._send({'error':'JSON content type required'},415)
        except (ValueError, UnicodeError):
            return self._send({'jsonrpc':'2.0','id':None,'error':{'code':-32700,'message':'Invalid JSON body'}})
        if not admin:
            rid = body.get('id') if isinstance(body,dict) else None
            if (not isinstance(body,dict) or body.get('jsonrpc') != '2.0' or 'id' not in body
                    or type(rid) not in (str,int,type(None)) or not isinstance(body.get('params'),dict)):
                return self._send({'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Invalid request'}})
            method = body.get('method')
            if method not in ('Start','Stop','Update'):
                return self._send({'jsonrpc':'2.0','id':rid,'error':{'code':-32601,'message':'Unknown method'}})
            try:
                error = self.server.engine.handle(method,body['params'])
                return self._send({'jsonrpc':'2.0','id':rid,'result':[error or 'OK']})
            except ValueError as ex:
                return self._send({'jsonrpc':'2.0','id':rid,'error':{'code':-32602,'message':str(ex)}})
            except Exception as ex:
                LOG.error('event_persistence_failed type=%s',type(ex).__name__)
                return self._send({'jsonrpc':'2.0','id':rid,'result':['Unable to persist or process event']})
        if not isinstance(body,dict):
            return self._send({'error':'Object required'},400)
        try:
            if self.path == '/api/kerios':
                proposed = self.server.registry.proposed(body)
                current = self.server.registry.get_client(proposed['id'])
                identity_fields = ('host','port','subnets','prefix','suffix','default_domain')
                if current and any(proposed[k] != current.cfg[k] for k in identity_fields):
                    if any(r['target']==proposed['id'] and not r['complete'] for r in self.server.engine.store.all()):
                        return self._send({'error':'Drain target leases before changing host, routing or username settings'},409)
                return self._send({'id':self.server.registry.upsert(body)})
            if self.path == '/api/kerios/delete':
                # Retain connection details until every associated lease is revoked.
                if any(r['target']==body.get('id') and not r['complete'] for r in self.server.engine.store.all()):
                    return self._send({'error':'Target has active or pending leases; revoke them before deletion'},409)
                self.server.registry.delete(body.get('id'))
                return self._send({'ok':True})
            if self.path == '/api/kerios/test':
                client = self.server.registry.get_client(body.get('id'))
                if not client:
                    return self._send({'error':'Target not found'},404)
                return self._send({'ok':True,'activeHosts':client.test()})
        except ValueError as ex:
            return self._send({'error':str(ex)},400)
        except Exception as ex:
            LOG.warning('management_operation_failed type=%s',type(ex).__name__)
            return self._send({'error':'Operation failed; inspect service logs and target access'},400)
        self._send({'error':'Not found'},404)

    def log_message(self, *args):
        pass


def create_server(address, registry, engine, settings):
    settings.validate()
    context = None
    if settings.cert_file:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(settings.cert_file, settings.key_file)
    server = BoundedServer(address,Handler)
    server.registry, server.engine, server.settings = registry, engine, settings
    server.tls_context = context
    server.slots = threading.BoundedSemaphore(settings.max_workers)
    server.csrf = secrets.token_urlsafe(32)
    return server


def main():
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    os.umask(0o077)
    settings = Settings(**{key:os.getenv(key.upper(),'') for key in
                          ('bridge_user','bridge_pass','admin_user','admin_pass','cert_file','key_file','public_origin')},
                        allow_http=os.getenv('ALLOW_HTTP','false').lower()=='true')
    settings.validate()
    registry = Registry(os.getenv('CONFIG_PATH','/data/kerios.json'))
    store = StateStore(os.getenv('STATE_PATH','/data/state.sqlite3'))
    def positive_env(name,default):
        value = int(os.getenv(name,str(default)))
        if not 1 <= value <= 315360000:
            raise ValueError(f'Invalid {name}')
        return value
    engine = Engine(registry,store,verified_ttl=positive_env('VERIFIED_TTL',30),
                    reconcile_interval=positive_env('RECONCILE_INTERVAL',60),fallback_ttl=positive_env('FALLBACK_TTL',3600))
    server = create_server((os.getenv('LISTEN_ADDR','0.0.0.0'),int(os.getenv('LISTEN_PORT','9090'))),registry,engine,settings)
    def shutdown(*args):
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,shutdown)
    signal.signal(signal.SIGINT,shutdown)
    engine.start()
    LOG.info('bridge_started port=%s targets=%s',server.server_port,len(registry.public_list()))
    try:
        server.serve_forever()
    finally:
        server.server_close(); engine.close(); store.close()
