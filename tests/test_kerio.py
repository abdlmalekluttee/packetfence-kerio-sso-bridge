import ssl
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from bridge.kerio import KerioClient, KerioError
from tests.helpers import Appliance, CONFIG, host, Clock

class KerioTests(unittest.TestCase):
    def test_domain_comparison_never_strips_realm(self):
        c=Appliance()
        self.assertTrue(c.matches(host(), 'alice'))
        self.assertTrue(c.matches(host(), 'alice@example.test'))
        self.assertFalse(c.matches(host(domain='other.test'), 'alice@example.test'))
        self.assertFalse(c.matches(host(), 'alice@other.test'))

    def test_explicit_short_domain_alias_is_shared_by_comparison_and_lookup(self):
        c=Appliance({'domain_aliases':{'example':'example.test'}})
        for name in ('alice@EXAMPLE',r'EXAMPLE\alice','alice@example.test'):
            with self.subTest(name=name):
                self.assertEqual(c.user_name(name),'alice@example.test')
                self.assertTrue(c.matches(host(),name))
                self.assertEqual(c.resolve_user(name)[1]['id'],'u-alice')
        self.assertFalse(c.matches(host(),'alice@other'))
        self.assertFalse(c.matches(host(domain='other.test'),'alice@example'))
        self.assertFalse(Appliance().matches(host(),'alice@example'))
        self.assertEqual(c.mutations(),[])

    def test_ipv6_alias_and_pagination(self):
        c=Appliance(); c.page_size=1
        c.hosts=[host(ip='192.0.2.11'),host(ip='192.0.2.10')]
        c.hosts[0]['ip6Addresses']=[]; c.hosts[0]['id']='h0'
        self.assertEqual(c.host_by_ip('2001:0db8:0:0:0:0:0:10')['id'],'h1')
        self.assertEqual(len([m for m,p in c.calls if m=='ActiveHosts.get']),2)
        c.host_by_ip('192.0.2.10')
        self.assertEqual(len([m for m,p in c.calls if m=='ActiveHosts.get']),2)

    def test_session_expiry_reauthenticates_once(self):
        c=Appliance(); count=[0]
        def expired(p):
            count[0]+=1
            if count[0]==1: return {'id':p['id'],'error':{'code':-32001,'message':'expired'}}
            return {'id':p['id'],'result':{'list':[],'totalItems':0}}
        c.fail['ActiveHosts.get']=expired
        self.assertIsNone(c.host_by_ip('192.0.2.10'))
        self.assertEqual(sum(m=='Session.login' for m,p in c.calls),2)

    def test_malformed_response_is_not_success(self):
        for response in ({}, {'id':999,'result':{}}, {'id':2}, []):
            with self.subTest(response=response):
                c=Appliance(); c.fail['ActiveHosts.get']=lambda p:response
                with self.assertRaises(KerioError): c.host_by_ip('192.0.2.10')

    def test_empty_logout_never_reaches_network(self):
        c=Appliance()
        with self.assertRaises(ValueError): c.logout('')
        self.assertEqual(c.calls,[])

    def test_local_name_collision_warning_allows_exact_domain_resolution(self):
        c=Appliance(); exchange=c._exchange
        def response(payload,headers):
            body=exchange(payload,headers)
            if payload['method']=='Users.get':
                body['result']['warnings']=[{'inputIndex':-1,'code':8003,
                    'message':'Some user names are in conflict with users in the local user database.',
                    'messageParameters':{'positionalParameters':[],'plurality':1}}]
            return body
        c._exchange=response
        domain,user=c.resolve_user('alice@example.test')
        self.assertEqual((domain,user['id']),('d1','u-alice'))
        with self.assertRaises(KerioError):c.resolve_user('alice@other.test')
        self.assertEqual(c.mutations(),[])

    def test_directory_authentication_and_unknown_warnings_still_block(self):
        for warnings in ([{'code':8004}],[{'code':9999}],
                         [{'code':8003},{'code':8004}],{'code':8003},['8003']):
            with self.subTest(warnings=warnings):
                c=Appliance(); exchange=c._exchange
                def response(payload,headers):
                    body=exchange(payload,headers)
                    if payload['method']=='Users.get':body['result']['warnings']=warnings
                    return body
                c._exchange=response
                with self.assertRaises(KerioError):c.resolve_user('alice@example.test')
                self.assertEqual(c.mutations(),[])

    def test_name_collision_warning_does_not_hide_same_domain_duplicates(self):
        c=Appliance();exchange=c._exchange
        c.users.append({'id':'another-alice','credentials':{'userName':'alice'}})
        def response(payload,headers):
            body=exchange(payload,headers)
            if payload['method']=='Users.get':body['result']['warnings']=[{'code':8003}]
            return body
        c._exchange=response
        with self.assertRaisesRegex(KerioError,'not uniquely resolved'):
            c.resolve_user('alice@example.test')

    def test_name_collision_warning_is_not_accepted_on_other_calls_or_with_errors(self):
        for method,result in [('Users.set',{'warnings':[{'code':8003}]}),
                              ('ActiveHosts.get',{'warnings':[{'code':8003}]}),
                              ('Users.get',{'warnings':[{'code':8003}],'errors':[{'code':8002}]})]:
            with self.subTest(method=method):
                c=Appliance()
                c.fail[method]=lambda p:{'id':p['id'],'result':result}
                with self.assertRaises(KerioError):c.call(method,{})

    def test_default_tls_and_ipv6_url(self):
        cfg={k:v for k,v in CONFIG.items() if k!='verify'}; cfg['host']='2001:db8::1'
        c=KerioClient(cfg)
        self.assertEqual(c._ctx.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(c._ctx.check_hostname)
        self.assertIn('https://[2001:db8::1]:4081/',c.url)

    def test_duplicate_ip_snapshot_is_ambiguous(self):
        c=Appliance(); c.hosts.append(host())
        with self.assertRaises(KerioError): c.host_by_ip('192.0.2.10')

    def test_outage_backoff_is_shared_across_different_ips(self):
        c=Appliance(); clock=Clock(); c.clock=clock
        c.fail['ActiveHosts.get']=KerioError('offline')
        with self.assertRaises(KerioError): c.host_by_ip('192.0.2.10')
        count=len(c.calls)
        with self.assertRaises(KerioError): c.host_by_ip('192.0.2.20')
        self.assertEqual(len(c.calls),count)
        c.fail.clear();clock.advance(3)
        self.assertIsNotNone(c.host_by_ip('192.0.2.10'))

    def test_total_response_deadline_limits_trickle_reads(self):
        c=KerioClient(CONFIG);clock=Clock();c.clock=clock;c._deadline=1020
        def read(size): clock.advance(25);return b'{}'
        response=SimpleNamespace(status=200,getheaders=lambda:[],read=read,read1=read)
        with patch('bridge.kerio.http.client.HTTPSConnection') as connection, patch('bridge.kerio.time.monotonic',side_effect=clock):
            connection.return_value.getresponse.return_value=response
            with self.assertRaises(KerioError): c._exchange({'id':1}, {})

if __name__=='__main__': unittest.main()
