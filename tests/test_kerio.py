import ssl
import unittest
from bridge.kerio import KerioClient, KerioError
from tests.helpers import Appliance, CONFIG, host

class KerioTests(unittest.TestCase):
    def test_domain_comparison_never_strips_realm(self):
        c=Appliance()
        self.assertTrue(c.matches(host(), 'alice'))
        self.assertTrue(c.matches(host(), 'alice@example.test'))
        self.assertFalse(c.matches(host(domain='other.test'), 'alice@example.test'))
        self.assertFalse(c.matches(host(), 'alice@other.test'))

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

    def test_default_tls_and_ipv6_url(self):
        cfg={k:v for k,v in CONFIG.items() if k!='verify'}; cfg['host']='2001:db8::1'
        c=KerioClient(cfg)
        self.assertEqual(c._ctx.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(c._ctx.check_hostname)
        self.assertIn('https://[2001:db8::1]:4081/',c.url)

    def test_duplicate_ip_snapshot_is_ambiguous(self):
        c=Appliance(); c.hosts.append(host())
        with self.assertRaises(KerioError): c.host_by_ip('192.0.2.10')

if __name__=='__main__': unittest.main()
