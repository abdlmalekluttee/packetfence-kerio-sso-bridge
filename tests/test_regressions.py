"""Whole-branch review regressions: lifecycle, aliases and read amplification."""
import threading
import json
import time
import socket
import ssl
import sqlite3
from pathlib import Path
import unittest
from unittest.mock import patch
from tests import test_engine
from tests.test_engine import event
from tests.helpers import host
from tests.helpers import Appliance, CONFIG
from tests import test_server
from bridge.kerio import KerioClient, KerioError


class LifecycleRegressions(unittest.TestCase):
    setUp = test_engine.EngineTests.setUp
    def test_periodic_sweep_shares_host_snapshot(self):
        self.client.hosts = [{**host(ip=f'192.0.2.{n}'), 'id':f'h{n}', 'ip6Addresses':[]}
                             for n in range(1, 101)]
        for n in range(1, 101):
            self.assertIsNone(self.engine.handle('Start', event(ip=f'192.0.2.{n}', timeout=1000)))
        self.client.calls.clear(); self.clock.advance(61); self.engine.tick()
        self.assertLessEqual(sum(m == 'ActiveHosts.get' for m, p in self.client.calls), 2)
        self.assertEqual(self.client.mutations(), [])

    def test_expiring_alias_preserves_other_active_lease(self):
        self.engine.handle('Start', event(timeout=1))
        self.engine.handle('Start', event(ip='2001:db8::10', timeout=100))
        self.client.calls.clear(); self.clock.advance(2); self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')
        self.assertEqual(self.client.mutations(), [])
        self.clock.advance(100); self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'], '')

    def test_alias_with_different_identity_refuses_host_rebinding(self):
        self.engine.handle('Start', event())
        self.client.calls.clear()
        self.assertIsNotNone(self.engine.handle('Start', event('bob', ip='2001:db8::10')))
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')
        self.assertEqual(self.client.mutations(), [])

    def test_equivalent_domain_forms_stop_same_lease(self):
        self.engine.handle('Start', event('alice'))
        self.assertIsNone(self.engine.handle('Stop', event('alice@example.test')))
        self.assertEqual(self.client.hosts[0]['user']['name'], '')
        self.assertTrue(self.store.get('192.0.2.10')['complete'])

    def test_renewal_wins_over_stale_expiry_read(self):
        self.engine.handle('Start', event(timeout=1)); self.clock.advance(2)
        reached = threading.Event(); release = threading.Event(); first = [True]
        original = self.store.get
        def stale_read(ip):
            row = original(ip)
            if first[0]:
                first[0] = False; reached.set()
                if not release.wait(3): raise RuntimeError('Test barrier timed out')
            return row
        results = []
        with patch.object(self.store, 'get', side_effect=stale_read):
            worker = threading.Thread(target=self.engine.tick)
            worker.start(); self.assertTrue(reached.wait(2))
            renewal = threading.Thread(target=lambda: results.append(self.engine.handle('Update', event(timeout=100))))
            renewal.start()
            try:
                for _ in range(200):
                    if original('192.0.2.10')['expires'] > self.clock(): break
                    threading.Event().wait(.005)
                self.assertGreater(original('192.0.2.10')['expires'], self.clock())
            finally:
                release.set(); worker.join(3); renewal.join(3)
            self.assertFalse(worker.is_alive() or renewal.is_alive())
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')
        self.assertEqual(original('192.0.2.10')['desired'], 'active')

    def test_failed_durable_receive_never_mutates_remote(self):
        with patch.object(self.store, 'update', side_effect=sqlite3.OperationalError('disk full')):
            with self.assertRaises(sqlite3.OperationalError):
                self.engine.handle('Start', event('bob'))
        self.assertEqual(self.client.mutations(), [])
        self.assertIsNone(self.store.get('192.0.2.10'))

    def test_failed_final_state_write_returns_pending_and_recovers(self):
        original = self.store.update
        def update(ip, transform):
            def fail_verified(old):
                new = transform(old)
                if new and new.get('verified'):
                    raise sqlite3.OperationalError('disk full')
                return new
            return original(ip, fail_verified)
        with patch.object(self.store, 'update', side_effect=update):
            self.assertIsNotNone(self.engine.handle('Start', event('bob')))
        self.assertEqual(self.client.hosts[0]['user']['name'], 'bob')
        self.assertEqual(self.engine.status()['pending'], 1)
        self.clock.advance(3); self.engine.tick()
        self.assertEqual(self.engine.status()['pending'], 0)

    def test_stop_during_delayed_failed_login_cannot_resurrect(self):
        self.client.hosts[0] = host(user='')
        reached = threading.Event(); release = threading.Event()
        def fail(payload):
            reached.set()
            if not release.wait(3): raise RuntimeError('Test barrier timed out')
            raise KerioError('Delayed login failure')
        self.client.fail['ActiveHosts.login'] = fail
        start = threading.Thread(target=lambda: self.engine.handle('Start', event()))
        start.start(); self.assertTrue(reached.wait(2))
        stop = threading.Thread(target=lambda: self.engine.handle('Stop', event()))
        stop.start()
        try:
            for _ in range(200):
                if self.store.get('192.0.2.10')['desired'] == 'stop': break
                threading.Event().wait(.005)
            self.assertEqual(self.store.get('192.0.2.10')['desired'], 'stop')
        finally:
            release.set(); start.join(3); stop.join(3)
        self.client.fail.clear(); self.clock.advance(10); self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'], '')
        self.assertTrue(self.store.get('192.0.2.10')['complete'])


class ConfigurationRaces(unittest.TestCase):
    request = test_server.ServerTests.request
    shutdown = test_server.ServerTests.shutdown

    def setUp(self):
        test_server.ServerTests.setUp(self)
        factory = patch('bridge.registry.KerioClient', side_effect=lambda cfg: Appliance(cfg))
        factory.start(); self.addCleanup(factory.stop)
        self.registry.upsert({**CONFIG, 'override_manual':True})
        self.client = self.registry.get_client('k1')
        token = json.loads(self.request('GET', '/api/session')[1])['csrf']
        self.headers = {'X-CSRF-Token':token, 'Origin':f'http://127.0.0.1:{self.server.server_port}'}

    def test_deleted_target_cannot_receive_late_login(self):
        reached = threading.Event(); release = threading.Event(); original = self.engine._select
        def select(row):
            result = original(row); reached.set()
            if not release.wait(3): raise RuntimeError('Test barrier timed out')
            return result
        results = []
        with patch.object(self.engine, '_select', side_effect=select):
            start = threading.Thread(target=lambda: results.append(self.engine.handle('Start', event('bob'))))
            start.start(); self.assertTrue(reached.wait(2))
            try:
                status, _, _ = self.request('POST', '/api/kerios/delete', {'id':'k1'}, headers=self.headers)
            finally:
                release.set(); start.join(3)
        self.assertFalse(start.is_alive())
        self.assertEqual(status, 200)
        self.assertEqual(self.client.mutations(), [])
        self.assertIsNotNone(results[0])

    def test_policy_save_waits_for_old_policy_mutations(self):
        self.client.hosts[0]['authMethod'] = 'AuthMethodAutomatic'
        reached = threading.Event(); release = threading.Event(); timeline = []; responses = []
        original = self.client.prepare_conflict; exchange = self.client._exchange
        def pause(*args):
            reached.set()
            if not release.wait(3): raise RuntimeError('Test barrier timed out')
            return original(*args)
        def record(payload, headers):
            if payload['method'] in ('Users.set', 'ActiveHosts.login', 'ActiveHosts.logout'):
                timeline.append(('mutation', time.monotonic()))
            return exchange(payload, headers)
        def save():
            responses.append(self.request('POST', '/api/kerios', {**CONFIG, 'override_manual':False}, headers=self.headers)[0])
            timeline.append(('saved', time.monotonic()))
        with patch.object(self.client, 'prepare_conflict', side_effect=pause), patch.object(self.client, '_exchange', side_effect=record):
            start = threading.Thread(target=lambda: self.engine.handle('Start', event('bob')))
            start.start(); self.assertTrue(reached.wait(2))
            editing = threading.Thread(target=save); editing.start()
            time.sleep(.1); release.set(); start.join(3); editing.join(3)
        self.assertFalse(start.is_alive() or editing.is_alive())
        self.assertEqual(responses, [200])
        saved = next(t for what, t in timeline if what == 'saved')
        self.assertTrue(all(t <= saved for what, t in timeline if what == 'mutation'), timeline)


class TransportDeadline(unittest.TestCase):
    def test_response_header_trickle_obeys_absolute_deadline(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fixtures = Path(__file__).parent / 'fixtures'
        context.load_cert_chain(fixtures / 'test-cert.pem', fixtures / 'test-key.pem')
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1)
        listener.settimeout(2); finished = threading.Event()
        def serve():
            try:
                raw, _ = listener.accept()
                with context.wrap_socket(raw, server_side=True) as conn:
                    conn.recv(8192); conn.sendall(b'HTTP/1.1 200 OK\r\n')
                    for _ in range(24):
                        if finished.wait(.05): return
                        conn.sendall(b'X-Trickle: yes\r\n')
                    conn.sendall(b'Content-Length: 2\r\n\r\n{}')
            except (OSError, ssl.SSLError):
                pass
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        client = KerioClient({**CONFIG, 'host':'127.0.0.1', 'port':listener.getsockname()[1], 'verify':False})
        try:
            with client.transaction():
                client._deadline = time.monotonic() + .2
                started = time.monotonic()
                with self.assertRaises(KerioError): client._exchange({'id':1}, {})
                elapsed = time.monotonic() - started
            self.assertLess(elapsed, .7)
        finally:
            finished.set(); listener.close(); thread.join(2)
