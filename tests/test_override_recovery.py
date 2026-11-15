import copy
import tempfile
import unittest
from pathlib import Path

from bridge.engine import Engine
from bridge.kerio import KerioError
from bridge.state import StateStore
from tests.helpers import Appliance,Clock,host
from tests.test_engine import Registry,event


class CutoffAppliance(Appliance):
    def __init__(self):
        super().__init__({'override_manual':True})
        self.hosts=[host(method='AuthMethodAutomatic')]
        self.pending=False;self.confirm=True;self.restore_automatic=False
        self.timestamps=None

    def _exchange(self,payload,headers):
        method=payload['method']
        if method in ('Session.getConfigTimestamp','Session.confirmConfig'):
            self.calls.append((method,copy.deepcopy(payload['params'])))
            if method=='Session.getConfigTimestamp':
                result={'clientTimestampList':self.timestamps if self.timestamps is not None else
                        ([{'name':'config','timestamp':17}] if self.pending else [])}
            else:
                result={'confirmed':self.confirm}
                if self.confirm:self.pending=False
            return {'id':payload['id'],'result':result}
        result=super()._exchange(payload,headers)
        if method=='Users.set':self.pending=True
        if method=='ActiveHosts.logout' and (self.pending or self.restore_automatic):
            self.hosts[0]=host(method='AuthMethodAutomatic')
        if method=='ActiveHosts.login' and self.pending:
            self.hosts[0]=host(method='AuthMethodAutomatic')
            return {'id':payload['id'],'error':{'code':1000}}
        return result


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.path=str(Path(tmp.name)/'state.db');self.store=StateStore(self.path)
        self.addCleanup(self.store.close)
        self.clock=Clock();self.client=CutoffAppliance();self.client.clock=self.clock
        self.registry=Registry(self.client);self.engine=Engine(self.registry,self.store,clock=self.clock)
        self.params=event('bob',timeout=3600)

    def methods(self):return [m for m,_ in self.client.mutations()]
    def resume(self,seconds=6):self.clock.advance(seconds);self.engine.tick()

    def test_confirms_configuration_and_settles_before_one_login(self):
        self.engine.handle('Start',self.params)
        self.assertEqual(self.methods(),['Users.set'])
        self.assertFalse(self.client.pending)
        methods=[m for m,_ in self.client.calls]
        self.assertLess(methods.index('Users.set'),methods.index('Session.confirmConfig'))
        self.assertLess(methods.index('Session.confirmConfig'),methods.index('Session.logout'))
        self.assertEqual(self.client.users[0]['autoLogin']['addresses']['value'],['192.0.2.20'])
        self.resume()
        self.assertEqual(self.client.hosts[0]['user']['name'],'bob')
        self.assertEqual(self.methods(),['Users.set','ActiveHosts.logout','ActiveHosts.login'])
        count=len(self.client.calls)
        for _ in range(100):self.engine.handle('Update',self.params)
        self.assertEqual(len(self.client.calls),count)
        self.assertEqual(self.store.get(self.params['ip'])['manual_recovery']['binds'],1)

    def test_recovery_survives_restart_after_exact_entry_is_removed(self):
        self.engine.handle('Start',self.params)
        self.store.close();self.store=StateStore(self.path)
        self.addCleanup(self.store.close)
        self.engine=Engine(self.registry,self.store,clock=self.clock)
        self.resume()
        self.assertEqual(self.client.hosts[0]['user']['name'],'bob')
        self.assertEqual(self.methods().count('Users.set'),1)

    def test_delayed_automatic_reappearance_uses_only_remaining_attempt(self):
        self.engine.handle('Start',self.params);self.resume()
        self.assertEqual(self.client.hosts[0]['user']['name'],'bob')
        self.client.hosts=[host(method='AuthMethodAutomatic')]
        self.resume(61)
        self.assertEqual(self.client.hosts[0]['user']['name'],'bob')
        self.client.hosts=[host(method='AuthMethodAutomatic')]
        self.resume(61)
        self.assertEqual(self.methods().count('Users.set'),1)
        self.assertEqual(self.methods().count('ActiveHosts.logout'),2)
        self.assertEqual(self.methods().count('ActiveHosts.login'),2)

    def test_configuration_not_confirmed_never_logs_out(self):
        self.client.confirm=False
        self.engine.handle('Start',self.params)
        self.resume(61)
        self.assertEqual(self.methods(),['Users.set'])
        self.assertEqual(self.client.hosts[0]['user']['name'],'alice')

    def test_unrelated_pending_configuration_is_not_confirmed_or_edited(self):
        self.client.pending=True
        self.engine.handle('Start',self.params)
        self.assertEqual(self.methods(),[])
        self.assertNotIn('Session.confirmConfig',[m for m,_ in self.client.calls])

    def test_malformed_timestamps_never_authorize_mutation(self):
        for invalid in ({},[{}],[{'name':'config','timestamp':True}],
                        [{'name':'config','timestamp':'17'}]):
            with self.subTest(invalid=invalid):
                self.setUp();self.client.timestamps=invalid
                self.engine.handle('Start',self.params)
                self.assertEqual(self.methods(),[])

    def test_lost_confirmation_response_recovers_with_independent_readback(self):
        original=self.client._exchange
        def exchange(payload,headers):
            result=original(payload,headers)
            if payload['method']=='Session.confirmConfig':
                raise TimeoutError('response lost after appliance applied confirmation')
            return result
        self.client._exchange=exchange
        self.engine.handle('Start',self.params)
        self.assertEqual(self.methods(),['Users.set'])
        self.client._exchange=original
        self.resume(61)
        self.assertEqual(self.methods(),['Users.set','ActiveHosts.logout','ActiveHosts.login'])

    def test_non_boolean_confirmation_never_authorizes_logout(self):
        self.client.confirm='true'
        self.engine.handle('Start',self.params)
        self.assertEqual(self.methods(),['Users.set'])
        self.assertIn('not confirmed',self.store.get(self.params['ip'])['error'])

    def test_reappearing_automatic_login_has_bounded_spaced_retries(self):
        self.client.restore_automatic=True
        self.engine.handle('Start',self.params);self.resume()
        self.assertNotIn('ActiveHosts.login',self.methods())
        count=self.methods().count('ActiveHosts.logout')
        for _ in range(100):self.engine.handle('Update',self.params);self.engine.tick()
        self.assertEqual(self.methods().count('ActiveHosts.logout'),count)
        for _ in range(10):self.resume(61)
        self.assertEqual(self.methods().count('ActiveHosts.logout'),2)
        self.assertEqual(self.methods().count('Users.set'),1)
        self.assertNotIn('ActiveHosts.login',self.methods())

    def test_changed_context_or_expired_proof_blocks_host_mutations(self):
        changes=[lambda:setattr(self.client,'hosts',[host(method='AuthMethodAutomatic',user='someone')]),
                 lambda:self.client.hosts[0].update(id='new-host'),
                 lambda:self.client.users[0]['autoLogin']['addresses']['value'].append('192.0.2.99'),
                 lambda:self.client.cfg.update(override_manual=False),
                 lambda:self.clock.advance(901)]
        for change in changes:
            with self.subTest(change=change):
                # Independent actual engine/client/store state for each case.
                self.setUp()
                self.engine.handle('Start',self.params);self.client.calls.clear()
                change();self.resume()
                self.assertEqual(self.client.mutations(),[])

    def test_no_proof_does_not_bypass_missing_exact_rule(self):
        self.client.users[0]['autoLogin']['addresses']['value']=['192.0.2.20']
        self.engine.handle('Start',self.params)
        self.assertEqual(self.methods(),[])

    def test_stop_cancels_pending_override_recovery(self):
        self.engine.handle('Start',self.params);self.client.calls.clear()
        self.engine.handle('Stop',self.params);self.resume()
        self.assertEqual(self.methods(),[])
        self.assertTrue(self.store.get(self.params['ip'])['complete'])

    def test_anonymous_replacement_host_cannot_use_saved_recovery(self):
        self.engine.handle('Start',self.params);self.client.calls.clear()
        self.client.hosts=[{**host(user=''),'id':'replacement'}]
        self.resume()
        self.assertEqual(self.methods(),[])

    def test_anonymous_host_still_requires_unchanged_owner_policy(self):
        self.engine.handle('Start',self.params);self.client.calls.clear()
        self.client.hosts=[host(user='')]
        self.client.users[0]['autoLogin']['addresses']['value'].append('192.0.2.99')
        self.resume()
        self.assertEqual(self.methods(),[])

    def test_anonymous_original_host_recovers_after_interrupted_logout(self):
        self.engine.handle('Start',self.params);self.client.calls.clear()
        self.client.hosts=[host(user='')]
        self.resume()
        self.assertEqual(self.methods(),['ActiveHosts.login'])

    def test_rolled_back_write_reapplies_at_most_twice(self):
        original=copy.deepcopy(self.client.users[0])
        self.client.confirm=False
        self.engine.handle('Start',self.params)
        for _ in range(4):
            self.client.pending=False
            self.client.users[0]=copy.deepcopy(original)
            self.resume(301)
        self.assertEqual(self.methods(),['Users.set','Users.set'])

    def test_stale_packetfence_blocks_recovery(self):
        from unittest.mock import Mock
        self.engine.handle('Start',self.params);self.client.calls.clear()
        self.engine.source=Mock()
        self.engine.source.assess.return_value=('stale',self.clock())
        self.clock.advance(6)
        self.engine._reconcile(self.params['ip'],force=True)
        self.assertEqual(self.methods(),[])

    def test_stop_during_write_prevents_host_mutations(self):
        original=self.client._exchange
        def exchange(payload,headers):
            result=original(payload,headers)
            if payload['method']=='Users.set':
                self.store.update(self.params['ip'],lambda row:
                                  {**row,'desired':'stop','generation':row['generation']+1})
            return result
        self.client._exchange=exchange
        self.engine.handle('Start',self.params);self.resume()
        self.assertEqual(self.methods(),['Users.set'])
        self.assertEqual(self.store.get(self.params['ip'])['desired'],'stop')

    def test_stop_during_post_logout_read_prevents_login(self):
        self.engine.handle('Start',self.params)
        original=self.client._exchange
        def exchange(payload,headers):
            result=original(payload,headers)
            if payload['method']=='ActiveHosts.get' and not self.client.hosts[0]['user']['name']:
                self.store.update(self.params['ip'],lambda row:
                                  {**row,'desired':'stop','generation':row['generation']+1})
            return result
        self.client._exchange=exchange
        self.resume()
        self.assertEqual(self.methods(),['Users.set','ActiveHosts.logout'])
