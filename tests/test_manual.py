import copy
import unittest
from bridge.kerio import KerioError
from tests.helpers import Appliance, host

class ManualTests(unittest.TestCase):
    def test_override_disabled_refuses_automatic_conflict(self):
        c=Appliance(); h=host(method='AuthMethodAutomatic')
        with self.assertRaisesRegex(KerioError,'disabled'): c.prepare_conflict(h,'192.0.2.10','bob@example.test')
        self.assertEqual(c.mutations(),[])

    def test_enabled_removes_only_exact_ip_and_preserves_every_other_setting(self):
        c=Appliance({'override_manual':True}); original=copy.deepcopy(c.users[0])
        c.users[0]['data']={'rights':{'writeConfig':True}}
        c.prepare_conflict(host(method='AuthMethodAutomatic'),'192.0.2.10','bob@example.test')
        self.assertEqual(c.users[0]['autoLogin']['addresses'],{'enabled':True,'value':['192.0.2.20']})
        self.assertEqual(c.users[0]['autoLogin']['macAddresses'], original['autoLogin']['macAddresses'])
        self.assertEqual(c.users[0]['data'],{'rights':{'writeConfig':True}})
        writes=c.mutations()
        self.assertEqual([m for m,p in writes],['Users.set'])
        self.assertEqual(set(writes[0][1]['details']),{'autoLogin'})

    def test_matching_identity_never_changes_manual_configuration(self):
        c=Appliance({'override_manual':True})
        c.prepare_conflict(host(method='AuthMethodAutomatic'),'192.0.2.10','alice@example.test')
        self.assertEqual(c.calls,[])

    def test_unknown_target_user_does_not_destroy_existing_assignment(self):
        c=Appliance({'override_manual':True})
        with self.assertRaises(KerioError): c.prepare_conflict(host(method='AuthMethodAutomatic'),'192.0.2.10','missing@example.test')
        self.assertEqual(c.mutations(),[])

    def test_shared_rules_and_templates_are_not_automatically_edited(self):
        for field in ('addressGroup','macAddresses','template'):
            with self.subTest(field=field):
                c=Appliance({'override_manual':True})
                if field=='template': c.users[0]['useTemplate']=True
                else: c.users[0]['autoLogin'][field]['enabled']=True
                with self.assertRaises(KerioError): c.prepare_conflict(host(method='AuthMethodAutomatic'),'192.0.2.10','bob@example.test')
                self.assertEqual(c.mutations(),[])

    def test_item_errors_fail_without_attempting_active_login(self):
        c=Appliance({'override_manual':True})
        c.fail['Users.set']=lambda p:{'id':p['id'],'result':{'errors':[{'code':1004}]}}
        with self.assertRaises(KerioError): c.prepare_conflict(host(method='AuthMethodAutomatic'),'192.0.2.10','bob@example.test')
        self.assertEqual([m for m,p in c.mutations()],['Users.set'])

    def test_postwrite_mismatch_is_not_success(self):
        c=Appliance({'override_manual':True})
        c.fail['Users.set']=lambda p:{'id':p['id'],'result':{'errors':[]}}
        with self.assertRaisesRegex(KerioError,'verification'): c.prepare_conflict(host(method='AuthMethodAutomatic'),'192.0.2.10','bob@example.test')

    def test_unrecognized_automatic_rule_refused(self):
        c=Appliance({'override_manual':True}); c.users[0]['autoLogin']['addresses']['value']=['192.0.2.0/24']
        with self.assertRaises(KerioError): c.prepare_conflict(host(method='AuthMethodAutomatic'),'192.0.2.10','bob@example.test')
        self.assertEqual(c.mutations(),[])

    def test_reread_change_aborts_write(self):
        c=Appliance({'override_manual':True}); original=c._exchange; count=[0]
        def exchange(p,h):
            if p['method']=='Users.get' and p['params']['domainId']=='d1':
                count[0]+=1
                if count[0]==3: c.users[0]['autoLogin']['addresses']['value'].append('192.0.2.30')
            return original(p,h)
        c._exchange=exchange
        with self.assertRaisesRegex(KerioError,'changed'): c.prepare_conflict(host(method='AuthMethodAutomatic'),'192.0.2.10','bob@example.test')
        self.assertEqual(c.mutations(),[])
