import base64
import http.client
import json
import tempfile
import threading
import socket
import ssl
import unittest
from pathlib import Path
from bridge.server import create_server, Settings
from bridge.registry import Registry
from bridge.state import StateStore
from bridge.engine import Engine
from tests.helpers import CONFIG

class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.registry=Registry(str(Path(self.tmp.name)/'config.json'))
        self.store=StateStore(str(Path(self.tmp.name)/'state.db')); self.addCleanup(self.store.close)
        self.engine=Engine(self.registry,self.store)
        self.settings=Settings(bridge_user='pf',bridge_pass='pf-test-password',admin_user='admin',admin_pass='admin-test-password',allow_http=True)
        self.server=create_server(('127.0.0.1',0),self.registry,self.engine,self.settings)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.addCleanup(self.shutdown)
    def shutdown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)
    def request(self,method,path,body=None,auth='admin',headers=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=2)
        h={'Connection':'close'}
        if auth: h['Authorization']='Basic '+base64.b64encode(('admin:admin-test-password' if auth=='admin' else 'pf:pf-test-password').encode()).decode()
        if body is not None: h['Content-Type']='application/json'; body=json.dumps(body)
        h.update(headers or {})
        try:
            conn.request(method,path,body,h); res=conn.getresponse()
            return res.status,res.read(),dict(res.getheaders())
        finally: conn.close()
    def test_auth_boundaries_and_real_health(self):
        self.assertEqual(self.request('GET','/',auth=None)[0],401)
        self.assertEqual(self.request('GET','/api/kerios',auth='pf')[0],401)
        self.assertEqual(self.request('GET','/healthz',auth=None)[0],200)
    def test_csrf_and_origin_required_for_admin_mutations(self):
        data={'name':'test','host':'127.0.0.1','user':'api','password':'test-secret'}
        self.assertEqual(self.request('POST','/api/kerios',data)[0],403)
        token=json.loads(self.request('GET','/api/session')[1])['csrf']
        h={'X-CSRF-Token':token,'Origin':'https://foreign.invalid'}
        self.assertEqual(self.request('POST','/api/kerios',data,headers=h)[0],403)
        h['Origin']=f'http://127.0.0.1:{self.server.server_port}'
        self.assertEqual(self.request('POST','/api/kerios',data,headers=h)[0],200)
    def test_invalid_jsonrpc_envelope_returns_protocol_error(self):
        for data in ([],None,{'jsonrpc':'1.0','method':'Start'}, {'jsonrpc':'2.0','id':1,'method':'Start','params':[]}):
            status,body,_=self.request('POST','/',data,auth='pf',headers={'Content-Type':'application/json'})
            self.assertEqual(status,200); self.assertIn('error',json.loads(body))
    def test_oversized_body_and_nonjson_refused(self):
        self.assertEqual(self.request('POST','/',{'x':'a'*70000},auth='pf')[0],413)
        self.assertEqual(self.request('POST','/',{},auth='pf',headers={'Content-Type':'text/plain'})[0],415)
    def test_health_reflects_worker_failure(self):
        self.engine._worker_error='OSError'
        self.assertEqual(self.request('GET','/healthz',auth=None)[0],503)

    def test_target_identity_cannot_change_while_leases_exist(self):
        self.registry.upsert(CONFIG)
        self.store.update('192.0.2.10',lambda old:{'ip':'192.0.2.10','target':'k1','complete':False})
        token=json.loads(self.request('GET','/api/session')[1])['csrf']
        headers={'X-CSRF-Token':token,'Origin':f'http://127.0.0.1:{self.server.server_port}'}
        status,_,_=self.request('POST','/api/kerios',{**CONFIG,'host':'different.invalid'},headers=headers)
        self.assertEqual(status,409)
        self.assertEqual(self.registry.get_client('k1').cfg['host'],'kerio.invalid')
        status,_,_=self.request('POST','/api/kerios',
            {**CONFIG,'domain_aliases':{'example':'example.test'}},headers=headers)
        self.assertEqual(status,409)
        status,_,_=self.request('POST','/api/kerios',{**CONFIG,'domains':['example.test']},headers=headers)
        self.assertEqual(status,409)
        status,_,_=self.request('POST','/api/kerios',{**CONFIG,'override_manual':True},headers=headers)
        self.assertEqual(status,200)
    def test_default_credentials_and_implicit_plaintext_rejected(self):
        for kwargs in ({'admin_pass':'change-me-too'}, {'bridge_pass':''}, {'allow_http':False}):
            s=Settings(bridge_user='pf',bridge_pass='pf-test-password',admin_user='admin',admin_pass='admin-test-password',allow_http=True)
            for key,value in kwargs.items(): setattr(s,key,value)
            with self.assertRaises(ValueError): s.validate()

    def test_silent_tls_peer_does_not_block_other_clients(self):
        fixtures=Path(__file__).parent/'fixtures'
        settings=Settings(bridge_user='pf',bridge_pass='test-password',admin_user='admin',admin_pass='test-password',
                          cert_file=str(fixtures/'test-cert.pem'),key_file=str(fixtures/'test-key.pem'),io_timeout=.5)
        server=create_server(('127.0.0.1',0),self.registry,self.engine,settings)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        blocker=socket.create_connection(('127.0.0.1',server.server_port),timeout=1)
        conn=http.client.HTTPSConnection('127.0.0.1',server.server_port,timeout=2,context=ssl._create_unverified_context())
        try:
            conn.request('GET','/healthz');resp=conn.getresponse()
            self.assertEqual(resp.status,200);resp.read()
        finally:
            conn.close();blocker.close();server.shutdown();server.server_close();thread.join(2)
