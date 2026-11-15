import tempfile
import unittest
from pathlib import Path

from bridge.engine import Engine
from bridge.state import StateStore
from tests.helpers import Appliance, Clock, host
from tests.test_engine import Registry, event
from tests.test_packetfence import Source


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.clock=Clock();self.client=Appliance({'domain_aliases':{'example':'example.test'}})
        self.client.clock=self.clock
        self.source=Source(self.clock)
        self.store=StateStore(str(Path(temp.name)/'state.db'));self.addCleanup(self.store.close)
        self.engine=Engine(Registry(self.client),self.store,clock=self.clock,source=self.source)
        self.params=event('alice@example',timeout=86400)

    def stale(self):self.source.bindings[0]['end_time']='1970-01-01 00:15:00'

    def test_stale_source_preserves_existing_portal_host_even_on_stop(self):
        self.stale();self.client.hosts[0]['authMethod']='AuthMethodSslWeb'
        self.engine.handle('Start',self.params)
        self.clock.advance(61);self.engine.tick()
        self.engine.handle('Stop',self.params)
        self.clock.advance(61);self.engine.tick()
        self.assertEqual(self.client.mutations(),[])
        self.assertEqual(self.client.hosts[0]['user']['name'],'alice')
        self.assertEqual(self.engine.status()['held'],1)
        self.assertFalse(self.store.get(self.params['ip'])['complete'])

    def test_two_stale_observations_and_absence_retire_without_logout(self):
        self.stale();self.client.hosts=[]
        self.engine.handle('Start',self.params)
        for _ in range(20):self.engine.tick()
        self.assertFalse(self.store.get(self.params['ip'])['complete'])
        self.clock.advance(61);self.engine.tick()
        self.assertTrue(self.store.get(self.params['ip'])['complete'])
        self.assertEqual(self.client.mutations(),[])

    def test_unknown_source_preserves_hosts_and_does_not_retire_absent_lease(self):
        self.source.bindings=[];self.client.hosts=[]
        self.engine.handle('Start',self.params)
        self.clock.advance(61);self.engine.tick()
        self.assertFalse(self.store.get(self.params['ip'])['complete'])
        self.client.hosts=[host(user='bob')]
        self.clock.advance(61);self.engine.tick()
        self.assertEqual(self.client.mutations(),[])
        self.assertEqual(self.engine.status()['held'],1)

    def test_current_source_waits_then_logs_in_once(self):
        self.client.hosts=[]
        self.engine.handle('Start',self.params)
        self.assertEqual(self.engine.status()['waiting'],1)
        self.assertEqual(self.engine.status()['failed'],0)
        self.client.hosts=[host(user='')];self.clock.advance(6);self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'],'alice')
        calls=len(self.client.calls)
        for _ in range(100):self.engine.handle('Update',self.params)
        self.assertEqual(len(self.client.calls),calls)
        self.assertEqual([m for m,_ in self.client.mutations()],['ActiveHosts.login'])

    def test_unknown_source_outage_does_not_reuse_old_stale_evidence(self):
        from bridge.packetfence import SourceError
        self.stale();self.client.hosts=[]
        self.engine.handle('Start',self.params)
        self.clock.advance(61);self.source.failure=SourceError('down');self.engine.tick()
        self.assertFalse(self.store.get(self.params['ip'])['complete'])

    def test_event_during_absence_read_prevents_retirement(self):
        self.stale();self.client.hosts=[]
        self.engine.handle('Start',self.params);self.clock.advance(61)
        def renew(payload):
            self.store.update(self.params['ip'],lambda old:{**old,'updated':self.clock(),'expires':999999})
            return {'jsonrpc':'2.0','id':payload['id'],'result':{'list':[],'totalItems':0}}
        self.client.fail['ActiveHosts.get']=renew
        self.engine.tick()
        self.assertFalse(self.store.get(self.params['ip'])['complete'])

    def test_recent_renewal_restarts_retirement_confirmation(self):
        self.stale();self.client.hosts=[]
        self.engine.handle('Start',self.params);self.clock.advance(59)
        self.engine.handle('Update',self.params);self.clock.advance(2);self.engine.tick()
        self.assertFalse(self.store.get(self.params['ip'])['complete'])
        self.clock.advance(61);self.engine.tick()
        self.assertTrue(self.store.get(self.params['ip'])['complete'])

    def test_unusable_event_addresses_never_create_leases_or_call_apis(self):
        for ip in ['169.254.10.2','fe80::1','127.0.0.1','0.0.0.0','::','::1','224.0.0.1','ff02::1']:
            self.assertIsNone(self.engine.handle('Start',{**self.params,'ip':ip}))
        self.assertEqual(self.store.all(),[])
        self.assertEqual(self.client.calls,[])
        self.assertEqual(self.source.calls,[])

    def test_source_batch_budget_deferral_wakes_on_next_observation(self):
        self.source.refresh([self.params])
        self.source.bindings[0]['ip']='192.0.2.11'
        self.client.hosts=[host(user='',ip='192.0.2.11')]
        params={**self.params,'ip':'192.0.2.11'}
        self.engine.handle('Start',params)
        self.assertEqual(self.client.mutations(),[])
        self.clock.advance(1);self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'],'alice')
