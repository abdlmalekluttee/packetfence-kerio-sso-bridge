import copy
import unittest
import threading
import ssl
import hashlib
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

from bridge.packetfence import PacketFence, SourceError
from tests.helpers import Clock


ROW = {'ip':'192.0.2.10', 'mac':'020000000001', 'user':'alice@example', 'updated':1000}


class Source(PacketFence):
    """Replace only the HTTPS exchange; exercise real queries, parsing and cache."""
    def __init__(self, clock):
        super().__init__({'host':'pf.invalid','username':'observer','password':'test',
                          'timezone':'UTC'}, clock=clock)
        self.calls = []
        self.bindings = [{'ip':'192.0.2.10','mac':'02:00:00:00:00:01',
                          'start_time':'1970-01-01 00:01:00','end_time':'0000-00-00 00:00:00'}]
        self.nodes = [{'mac':'02:00:00:00:00:01','pid':r'EXAMPLE\alice','status':'reg'}]
        self.failure = None
        self.extra = {}

    def _exchange(self, path, payload, token):
        self.calls.append((path, copy.deepcopy(payload)))
        if self.failure:
            raise self.failure
        if path == '/login':
            return {'token':'opaque'}
        values = self.bindings if path == '/ip4logs/search' else self.nodes
        return {'items':copy.deepcopy(values),'status':200, **self.extra}


def canonical(name):
    return name.replace('EXAMPLE\\', '').replace('@example', '').casefold()


class PacketFenceTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.pf = Source(self.clock)

    def test_full_identity_and_alias_confirm_current_binding(self):
        self.assertEqual(self.pf.check(ROW, canonical), 'current')
        self.assertEqual([p for p,_ in self.pf.calls], ['/login','/ip4logs/search','/nodes/search'])
        for _ in range(100):
            self.assertEqual(self.pf.check(ROW, canonical), 'current')
        self.assertEqual(len(self.pf.calls), 3)
        self.assertEqual(self.pf.calls[1][1]['query']['values'][0],
                         {'field':'ip','op':'equals','value':'192.0.2.10'})

    def test_ended_binding_is_stale_but_future_expiry_is_current(self):
        self.pf.bindings[0]['end_time'] = '1970-01-01 00:15:00'
        self.assertEqual(self.pf.check(ROW, canonical), 'stale')
        self.clock.advance(61)
        self.pf.bindings[0]['end_time'] = '1970-01-01 01:00:00'
        self.assertEqual(self.pf.check(ROW, canonical), 'current')

    def test_newer_mac_or_user_cannot_validate_old_identity(self):
        for field,value in [('mac','020000000099'),('user','bob@example')]:
            with self.subTest(field=field):
                self.assertEqual(self.pf.check({**ROW,field:value}, canonical), 'stale')

    def test_missing_ambiguous_and_malformed_data_are_unknown(self):
        variants = [([],self.pf.nodes), (self.pf.bindings*2,self.pf.nodes),
                    (self.pf.bindings,[]), (self.pf.bindings,self.pf.nodes*2),
                    ([{**self.pf.bindings[0],'end_time':'broken'}],self.pf.nodes)]
        for bindings,nodes in variants:
            with self.subTest(bindings=bindings,nodes=nodes):
                pf = Source(self.clock); pf.bindings=bindings;pf.nodes=nodes
                self.assertEqual(pf.check(ROW,canonical),'unknown')

    def test_truncated_results_and_api_outage_never_mean_stale(self):
        self.pf.extra={'nextCursor':100}
        self.assertEqual(self.pf.check(ROW,canonical),'unknown')
        count=len(self.pf.calls)
        for _ in range(50):self.pf.check(ROW,canonical)
        self.assertEqual(len(self.pf.calls),count)
        self.clock.advance(61);self.pf.extra={};self.pf.failure=SourceError('unavailable')
        self.assertEqual(self.pf.check(ROW,canonical),'unknown')
        self.assertTrue(self.pf.error)

    def test_batch_reads_once_for_many_leases_and_expires(self):
        rows=[{**ROW,'ip':f'192.0.2.{i}'} for i in range(1,100)]
        self.pf.refresh(rows)
        self.assertEqual(len(self.pf.calls),3)
        self.pf.refresh(rows)
        self.assertEqual(len(self.pf.calls),3)
        self.clock.advance(61);self.pf.refresh(rows)
        self.assertEqual(len(self.pf.calls),5)

    def test_non_ipv4_or_missing_mac_is_unknown_without_network(self):
        for row in [{**ROW,'ip':'2001:db8::10'}, {**ROW,'mac':''}]:
            self.assertEqual(self.pf.check(row,canonical),'unknown')
        self.assertEqual(self.pf.calls,[])

    def test_bad_config_rejected(self):
        for change in [{'host':'https://pf.invalid/path'}, {'certificate_sha256':'bad'},
                       {'port':True}, {'username':''}, {'timezone':'invalid/timezone'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                PacketFence({'host':'pf.invalid','username':'observer','password':'test',**change})

    def test_missing_or_null_required_binding_fields_cannot_authorize(self):
        for field in ('end_time','start_time'):
            for value in (None,'missing','malformed'):
                with self.subTest(field=field,value=value):
                    pf=Source(self.clock)
                    if value=='missing':del pf.bindings[0][field]
                    else:pf.bindings[0][field]=value
                    self.assertEqual(pf.check(ROW,canonical),'unknown')

    def test_per_lease_checks_cannot_bypass_batch_request_budget(self):
        rows=[{**ROW,'ip':f'198.51.100.{i}'} for i in range(1,201)]
        self.pf.bindings=[];self.pf.nodes=[]
        self.pf.refresh(rows)
        count=len(self.pf.calls)
        for row in rows:self.pf.check(row,canonical)
        self.assertEqual(len(self.pf.calls),count)
        self.clock.advance(1);self.pf.refresh(rows)
        self.assertGreater(len(self.pf.calls),count)

    def test_wrong_field_types_fail_closed_with_backoff(self):
        self.pf.bindings[0]['ip']=[]
        self.assertEqual(self.pf.check(ROW,canonical),'unknown')
        count=len(self.pf.calls)
        for _ in range(10):self.pf.refresh([ROW])
        self.assertEqual(len(self.pf.calls),count)
        self.assertTrue(self.pf.error)

    def test_future_binding_does_not_establish_current_ownership(self):
        self.pf.bindings[0]['start_time']='2100-01-01 00:00:00'
        self.assertEqual(self.pf.check(ROW,canonical),'unknown')

    def test_blocked_connection_is_bounded_without_spawning_retries(self):
        started=threading.Event();release=threading.Event();finished=threading.Event()
        connections=[];requests=[];errors=[]
        def connect(conn):
            connections.append(conn);started.set();release.wait(3)
        def run():
            try:pf._exchange('/login',{'password':'secret'},None)
            except SourceError as ex:errors.append(str(ex))
            finally:finished.set()
        pf=PacketFence({'host':'pf.invalid','username':'observer','password':'secret'})
        with patch('bridge.packetfence.REQUEST_TIMEOUT',0.15,create=True), \
             patch('http.client.HTTPSConnection.connect',connect), \
             patch('http.client.HTTPSConnection.request',lambda *args,**kw:requests.append(args)):
            thread=threading.Thread(target=run);thread.start()
            try:
                self.assertTrue(started.wait(1))
                self.assertTrue(finished.wait(.5),'DNS/connect work exceeded the request deadline')
                for _ in range(5):
                    with self.assertRaises(SourceError):pf._exchange('/login',{},None)
                self.assertEqual(len(connections),1)
            finally:
                release.set();thread.join(3)
                if getattr(pf,'_network_thread',None):pf._network_thread.join(2)
        self.assertTrue(errors)
        self.assertEqual(requests,[],'A timed-out connect must not send credentials later')

    def test_certificate_pin_is_checked_before_sending_credentials(self):
        received=[]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(200);self.end_headers();self.wfile.write(b'{"token":"opaque"}')
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        fixtures=Path(__file__).parent/'fixtures'
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(fixtures/'test-cert.pem',fixtures/'test-key.pem')
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        cfg={'host':'127.0.0.1','port':server.server_port,'username':'observer','password':'secret'}
        try:
            bad=PacketFence({**cfg,'certificate_sha256':'0'*64})
            with self.assertRaises(SourceError):bad._exchange('/login',{'password':'secret'},None)
            self.assertEqual(received,[])
            pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert((fixtures/'test-cert.pem').read_text())).hexdigest()
            good=PacketFence({**cfg,'certificate_sha256':pin})
            self.assertEqual(good._exchange('/login',{'password':'secret'},None),{'token':'opaque'})
            self.assertEqual(len(received),1)
        finally:
            server.shutdown();server.server_close();thread.join(2)
