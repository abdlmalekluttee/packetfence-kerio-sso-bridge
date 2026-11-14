import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from bridge.registry import Registry
from tests.helpers import CONFIG

class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'config.json'; self.r=Registry(str(self.path))
    def test_default_security_and_secret_redaction(self):
        c={k:v for k,v in CONFIG.items() if k!='verify'}
        eid=self.r.upsert(c); public=self.r.public_list()[0]
        self.assertTrue(public['verify']); self.assertFalse(public['override_manual'])
        self.assertNotIn('password',public); self.assertTrue(public['hasPassword'])
        self.assertEqual(Registry(str(self.path)).get_client(eid).cfg['password'],CONFIG['password'])
    def test_save_failure_leaves_memory_and_disk_unchanged(self):
        self.r.upsert(CONFIG); before=self.path.read_bytes()
        with patch('bridge.registry.os.replace',side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.r.upsert({**CONFIG,'id':'new'})
        self.assertEqual(self.path.read_bytes(),before)
        self.assertEqual(len(self.r.public_list()),1)
        self.assertIsNone(self.r.get_client('new'))
    def test_invalid_settings_rejected_before_mutation(self):
        for patchdata in ({'host':'x/path'}, {'port':0}, {'subnets':['nope']}, {'verify':'false'},
                          {'override_manual':'yes'},{'id':"bad'id"},{'enabled':1}, {'host':'x@evil'}, {'name':[] }):
            with self.subTest(patchdata=patchdata):
                with self.assertRaises(ValueError): self.r.upsert({**CONFIG,**patchdata})
        self.assertEqual(self.r.public_list(),[])
    def test_unedited_clients_reused_and_password_preserved(self):
        eid=self.r.upsert(CONFIG); client=self.r.get_client(eid)
        self.r.upsert({**CONFIG,'id':'k2'})
        self.assertIs(self.r.get_client(eid),client)
        c={k:v for k,v in CONFIG.items() if k!='password'}; c['name']='Renamed'
        self.r.upsert(c)
        self.assertEqual(self.r.get_client(eid).cfg['password'],CONFIG['password'])
    def test_corrupt_file_fails_closed(self):
        self.path.write_text('{broken')
        with self.assertRaises(ValueError): Registry(str(self.path))
    def test_subnet_routes_canonical_addresses(self):
        self.r.upsert({**CONFIG,'subnets':['2001:db8::/64']})
        self.assertEqual(len(self.r.candidates('2001:0db8::10')),1)
        self.assertEqual(self.r.candidates('192.0.2.10'),[])
