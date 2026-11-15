import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from bridge.engine import Engine
from bridge.state import StateStore
from bridge.kerio import KerioError
from tests.helpers import Appliance, Clock, host

class Registry:
    def __init__(self,*clients):
        self.clients={str(i):c for i,c in enumerate(clients)}
        self.lock=threading.RLock()
    def candidates(self,ip,user=None):
        return [(i,c) for i,c in self.clients.items() if user is None or c.accepts_user(user)]
    def ignores_user(self,user):
        return bool(self.clients) and not any(c.accepts_user(user) for c in self.clients.values())
    def get_client(self,eid): return self.clients.get(eid)
    @contextmanager
    def operation(self,eid,expected=None,pin=None):
        with self.lock:
            client=self.clients.get(eid)
            if expected is not None and client is not expected: raise KerioError('Target changed')
            if pin is not None: pin()
            yield client

def event(user='alice', **kw):
    return {'ip':'192.0.2.10','user':user,'mac':'02:00:00:00:00:01','timeout':100,**kw}

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.clock=Clock(); self.client=Appliance(); self.client.clock=self.clock; self.registry=Registry(self.client)
        self.store=StateStore(str(Path(self.tmp.name)/'state.db'))
        self.addCleanup(self.store.close)
        self.engine=Engine(self.registry,self.store,clock=self.clock)

    def test_matching_user_and_duplicate_events_do_not_mutate_or_refetch(self):
        self.assertIsNone(self.engine.handle('Start',event()))
        count=len(self.client.calls)
        for i in range(30): self.assertIsNone(self.engine.handle('Update',event()))
        self.assertEqual(self.client.mutations(),[])
        self.assertEqual(len(self.client.calls),count)

    def test_alias_renewals_keep_correct_session_and_equivalent_stop_is_recognized(self):
        self.client.cfg['domain_aliases']={'example':'example.test'}
        self.assertIsNone(self.engine.handle('Start',event('alice@example')))
        count=len(self.client.calls)
        for name in (r'EXAMPLE\alice','alice@example.test','alice@EXAMPLE')*10:
            self.assertIsNone(self.engine.handle('Update',event(name)))
        self.assertEqual(len(self.client.calls),count)
        self.assertEqual(self.client.mutations(),[])
        self.assertIsNone(self.engine.handle('Stop',event('alice@example.test')))
        self.assertEqual(self.client.hosts[0]['user']['name'],'')

    def test_alias_login_uses_canonical_domain_after_exact_user_validation(self):
        self.client.cfg['domain_aliases']={'example':'example.test'}
        self.client.hosts[0]=host(user='')
        self.assertIsNone(self.engine.handle('Start',event('bob@example')))
        self.assertEqual(self.client.hosts[0]['user']['name'],'bob')
        self.assertEqual([p['userName'] for m,p in self.client.mutations() if m=='ActiveHosts.login'],
                         ['bob@example.test'])

    def test_excluded_domain_events_leave_active_users_untouched_and_retire_pending(self):
        self.client.cfg['domains']=['example.test']
        self.assertIsNone(self.engine.handle('Start',event('alice@unmanaged.test')))
        self.assertEqual(self.client.calls,[])
        self.assertIsNone(self.store.get('192.0.2.10'))
        self.client.cfg['domains']=[]
        self.engine.handle('Start',event('alice@unmanaged.test'))
        self.client.calls.clear();self.client.cfg['domains']=['example.test']
        self.clock.advance(5);self.engine.tick()
        self.assertEqual(self.client.calls,[])
        self.assertTrue(self.store.get('192.0.2.10')['complete'])
        self.assertEqual(self.store.get('192.0.2.10')['desired'],'ignored')
        self.assertEqual(self.engine.status()['pending'],0)
        self.assertEqual(self.client.hosts[0]['user']['name'],'alice')

    def test_domain_scope_prevents_pinned_session_from_moving_to_another_firewall(self):
        self.client.cfg['domains']=['example.test']
        second=Appliance({'domains':['other.test'],'default_domain':'other.test'})
        second.hosts=[host(domain='other.test')];self.registry.clients['second']=second
        self.assertIsNone(self.engine.handle('Start',event('alice@example.test')))
        self.client.calls.clear();second.calls.clear()
        result=self.engine.handle('Start',event('alice@other.test'))
        self.assertIn('Assigned',result)
        self.assertEqual(self.client.mutations()+second.mutations(),[])

    def test_excluded_events_preserve_existing_managed_lease(self):
        self.client.cfg['domains']=['example.test']
        self.assertIsNone(self.engine.handle('Start',event('alice@example.test')))
        before=self.store.get('192.0.2.10');self.client.calls.clear()
        for method in ('Start','Update','Stop'):
            self.assertIsNone(self.engine.handle(method,event('alice@unmanaged.test')))
        self.assertEqual(self.store.get('192.0.2.10'),before)
        self.assertEqual(self.client.calls,[])

    def test_retired_excluded_lease_can_use_new_domain_target(self):
        self.client.cfg['domains']=['example.test']
        self.assertIsNone(self.engine.handle('Start',event('alice@example.test')))
        self.client.cfg['domains']=['other.test']
        self.clock.advance(61);self.engine.tick()
        self.assertEqual(self.store.get('192.0.2.10')['desired'],'ignored')
        self.assertTrue(self.store.get('192.0.2.10')['complete'])
        second=Appliance({'domains':['example.test']});second.clock=self.clock
        self.registry.clients['second']=second;self.client.calls.clear()
        self.assertIsNone(self.engine.handle('Start',event('alice@example.test')))
        self.assertEqual(self.store.get('192.0.2.10')['target'],'second')
        self.assertEqual(self.client.calls,[])
        self.assertEqual(second.mutations(),[])

    def test_domain_routing_selects_only_the_matching_firewall(self):
        self.client.cfg['domains']=['example.test']
        second=Appliance({'domains':['other.test'],'default_domain':'other.test'})
        second.hosts=[host(domain='other.test')];self.registry.clients['second']=second
        self.assertIsNone(self.engine.handle('Start',event('alice@other.test')))
        self.assertEqual(self.store.get('192.0.2.10')['target'],'second')
        self.assertEqual(self.client.calls,[])
        self.assertEqual(second.mutations(),[])

    def test_retired_alias_accepts_equivalent_stop_on_new_target(self):
        self.client.cfg.update(domains=['example.test'],domain_aliases={'example':'example.test'})
        self.engine.handle('Start',event('alice@example'))
        self.client.cfg['domains']=['other.test'];self.clock.advance(61);self.engine.tick()
        second=Appliance({'domains':['example.test'],'domain_aliases':{'example':'example.test'}})
        second.clock=self.clock;self.registry.clients['second']=second;self.client.calls.clear()
        self.assertIsNone(self.engine.handle('Stop',event('alice@example.test')))
        self.assertEqual(self.store.get('192.0.2.10')['target'],'second')
        self.assertEqual(self.store.get('192.0.2.10')['desired'],'stop')
        self.assertEqual(self.client.calls,[])
        self.assertEqual([m for m,p in second.mutations()],['ActiveHosts.logout'])

    def test_retired_snapshot_cannot_clear_a_concurrently_active_target_pin(self):
        self.client.cfg['domains']=['example.test']
        self.engine.handle('Start',event('alice@example.test'))
        self.client.cfg['domains']=['other.test'];self.clock.advance(61);self.engine.tick()
        second=Appliance({'domains':['example.test']});second.clock=self.clock
        self.registry.clients['second']=second;self.client.calls.clear()
        original=self.store.update;injected=[False]
        def intervening(ip,transform):
            if not injected[0]:
                injected[0]=True
                original(ip,lambda old:{**old,'desired':'active','complete':False,'generation':old['generation']+1})
            return original(ip,transform)
        self.store.update=intervening
        self.assertIn('Assigned',self.engine.handle('Start',event('alice@example.test')))
        self.assertEqual(self.store.get('192.0.2.10')['target'],'0')
        self.assertEqual(self.client.calls+second.calls,[])

    def test_renewal_refreshes_expiry_without_login(self):
        self.engine.handle('Start',event()); self.clock.advance(20)
        self.engine.handle('Update',event())
        self.clock.advance(81); self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'],'alice')
        self.clock.advance(20); self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'],'')

    def test_identity_change_and_old_owner_stop(self):
        self.engine.handle('Start',event())
        self.assertIsNone(self.engine.handle('Start',event('bob')))
        self.assertEqual(self.client.hosts[0]['user']['name'],'bob')
        self.client.calls.clear()
        self.assertIsNone(self.engine.handle('Stop',event('alice')))
        self.assertEqual(self.client.mutations(),[])

    def test_failed_stop_is_pending_and_retried(self):
        self.engine.handle('Start',event())
        self.client.fail['ActiveHosts.logout']=KerioError('offline')
        self.assertIsNotNone(self.engine.handle('Stop',event()))
        self.assertEqual(self.engine.status()['pending'],1)
        self.client.fail.clear(); self.clock.advance(3); self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'],'')
        self.assertEqual(self.engine.status()['pending'],0)

    def test_restart_reconciles_expired_lease(self):
        self.engine.handle('Start',event(timeout=1)); self.clock.advance(2)
        restarted=Engine(self.registry,self.store,clock=self.clock)
        restarted.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'],'')

    def test_unknown_stop_cannot_revoke_someone_else(self):
        self.assertIsNone(self.engine.handle('Stop',event('bob')))
        self.assertEqual(self.client.mutations(),[])

    def test_ambiguous_firewalls_never_receive_mutation(self):
        second=Appliance(); self.registry.clients['second']=second
        self.assertIn('ambiguous',self.engine.handle('Start',event()).lower())
        self.assertEqual(self.client.mutations()+second.mutations(),[])

    def test_mac_mismatch_refuses_identity_binding(self):
        self.client.hosts[0]['macAddress']='02:00:00:00:00:99'
        self.assertIsNotNone(self.engine.handle('Start',event('bob')))
        self.assertEqual(self.client.mutations(),[])

    def test_stop_supersedes_inflight_start(self):
        self.client.hosts[0]=host(user=''); reached=threading.Event(); release=threading.Event()
        original=self.client.prepare_conflict
        def pause(*a):
            original(*a); reached.set(); self.assertTrue(release.wait(3))
        self.client.prepare_conflict=pause
        out=[]
        start=threading.Thread(target=lambda:out.append(self.engine.handle('Start',event())))
        start.start(); self.assertTrue(reached.wait(2))
        stop=threading.Thread(target=lambda:out.append(self.engine.handle('Stop',event())))
        stop.start()
        # Wait for durable desired state, not a scheduler-dependent sleep.
        for _ in range(200):
            if self.store.get('192.0.2.10')['desired']=='stop': break
            threading.Event().wait(.005)
        self.assertEqual(self.store.get('192.0.2.10')['desired'],'stop')
        release.set(); start.join(3); stop.join(3)
        self.assertFalse(start.is_alive() or stop.is_alive())
        self.assertEqual(self.client.hosts[0]['user']['name'],'')

    def test_backoff_coalesces_repeated_failed_events(self):
        self.client.fail['ActiveHosts.get']=KerioError('offline')
        self.assertIsNotNone(self.engine.handle('Start',event()))
        count=len(self.client.calls)
        for _ in range(20): self.engine.handle('Update',event())
        self.assertEqual(len(self.client.calls),count)

    def test_capacity_is_bounded_and_invalid_events_do_not_create_rows(self):
        self.store.limit=1; self.engine.handle('Start',event())
        with self.assertRaises(ValueError): self.engine.handle('Start',event(ip='invalid'))
        with self.assertRaises(RuntimeError): self.engine.handle('Start',event(ip='192.0.2.20'))
        self.assertEqual(len(self.store.all()),1)

    def test_timeout_zero_uses_fallback_not_immediate_expiry(self):
        self.engine.handle('Start',event(timeout=0)); self.clock.advance(5); self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'],'alice')

    def test_manual_override_works_through_real_engine_and_can_be_disabled(self):
        self.client.hosts[0]['authMethod']='AuthMethodAutomatic'
        self.assertIsNotNone(self.engine.handle('Start',event('bob')))
        self.assertEqual(self.client.mutations(),[])
        self.client.cfg['override_manual']=True; self.clock.advance(3)
        self.assertIsNotNone(self.engine.handle('Start',event('bob')))
        self.clock.advance(6); self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'],'bob')
        self.assertEqual(self.client.users[0]['autoLogin']['addresses']['value'],['192.0.2.20'])
