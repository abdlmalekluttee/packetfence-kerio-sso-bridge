import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
import configure

class DeployTests(unittest.TestCase):
    def test_dotenv_rejects_multiline_values(self):
        with self.assertRaises(ValueError): configure.dotenv_value('line\nbreak')

    @unittest.skipUnless(shutil.which('docker'),'Docker Compose CLI not installed')
    def test_compose_preserves_literal_passwords(self):
        result=subprocess.run(['docker','compose','version'],capture_output=True)
        if result.returncode: self.skipTest('Compose plugin missing')
        examples=['abc$UNDEFINED_REVIEW_4918',"quote'and\"double",'trailing\\',r'back\slash',"abc\\'def",'space is allowed','$$both${HOME}','éArabicع']
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'compose.yml').write_text('services:\n  test:\n    image: unused\n    env_file: .env\n')
            values={f'TEST_{n}':v for n,v in enumerate(examples)}
            configure.write_env(root/'.env',values)
            proc=subprocess.run(['docker','compose','--project-directory',tmp,'-f',str(root/'compose.yml'),'config','--format','json'],capture_output=True,text=True,encoding='utf-8')
            self.assertEqual(proc.returncode,0,proc.stderr)
            # Compose's config serializer re-escapes literal dollars for a reusable
            # Compose file. Inspect dotenv-resolved interpolation values directly.
            resolved=subprocess.run(['docker','compose','--project-directory',tmp,'-f',str(root/'compose.yml'),'config','--environment'],capture_output=True,text=True,encoding='utf-8')
            self.assertEqual(resolved.returncode,0,resolved.stderr)
            env=dict(line.split('=',1) for line in resolved.stdout.splitlines() if line.startswith('TEST_'))
            self.assertEqual(env,values)

    def test_existing_configuration_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'.env';path.write_text('ADMIN_PASS=existing\n')
            with self.assertRaises(FileExistsError): configure.write_env(path,{'ADMIN_PASS':'new'})
            self.assertEqual(path.read_text(),'ADMIN_PASS=existing\n')

    def test_executable_refuses_missing_credentials(self):
        env={k:v for k,v in os.environ.items() if k not in ['ADMIN_PASS','BRIDGE_PASS','ADMIN_USER','BRIDGE_USER']}
        p=subprocess.run([os.sys.executable,'pf_kerio_sso_bridge.py'],env=env,capture_output=True,text=True,timeout=5)
        self.assertNotEqual(p.returncode,0)
        self.assertIn('must be configured',p.stderr)
