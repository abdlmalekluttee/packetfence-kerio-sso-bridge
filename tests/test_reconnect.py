import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bridge.engine import Engine
from bridge.kerio import KerioError
from bridge.state import StateStore
from tests.helpers import Appliance, Clock, host
from tests.test_engine import Registry, event


class ReconnectTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.clock = Clock()
        self.client = Appliance()
        self.client.clock = self.clock
        self.registry = Registry(self.client)
        self.path = str(Path(temp.name) / 'state.db')
        self.store = StateStore(self.path)
        self.addCleanup(lambda: self.store.close())
        self.engine = Engine(self.registry, self.store, clock=self.clock)
        self.params = event(timeout=86400)

    def long_missing_retry(self):
        self.client.hosts = []
        self.engine.handle('Start', self.params)
        for _ in range(10):
            row = self.store.get(self.params['ip'])
            self.clock.advance(row['next_try'] - self.clock())
            self.engine.tick()
        self.assertEqual(self.store.get(self.params['ip'])['next_try'] - self.clock(), 300)
        self.client.calls.clear()

    def reads(self):
        return sum(method == 'ActiveHosts.get' for method, _ in self.client.calls)

    def test_start_reconnect_checks_before_old_backoff_then_duplicates_are_noops(self):
        self.long_missing_retry()
        self.clock.advance(60)
        self.client.hosts = [host(user='')]
        self.assertIsNone(self.engine.handle('Start', self.params))
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')
        self.assertEqual([m for m, _ in self.client.mutations()], ['ActiveHosts.login'])
        count = len(self.client.calls)
        for _ in range(1000):
            self.assertIsNone(self.engine.handle('Start', self.params))
        self.assertEqual(len(self.client.calls), count)

    def test_update_reconnect_preserves_matching_portal_login(self):
        self.long_missing_retry()
        self.clock.advance(60)
        self.client.hosts = [host(method='AuthMethodSslWeb')]
        self.assertIsNone(self.engine.handle('Update', self.params))
        self.assertEqual(self.reads(), 1)
        self.assertEqual(self.client.mutations(), [])
        self.assertEqual(self.client.hosts[0]['authMethod'], 'AuthMethodSslWeb')

    def test_unpinned_missing_host_reconnect_selects_one_of_multiple_targets(self):
        second = Appliance()
        second.clock = self.clock
        second.hosts = []
        self.registry.clients['second'] = second
        self.long_missing_retry()
        self.assertIsNone(self.store.get(self.params['ip'])['target'])
        self.clock.advance(60)
        second.hosts = [host(user='')]
        self.assertIsNone(self.engine.handle('Update', self.params))
        self.assertEqual(self.store.get(self.params['ip'])['target'], 'second')
        self.assertEqual(second.hosts[0]['user']['name'], 'alice')
        self.assertEqual(self.client.mutations(), [])
        self.assertEqual([m for m, _ in second.mutations()], ['ActiveHosts.login'])

    def test_host_appearing_after_event_gets_followup_without_another_event(self):
        self.long_missing_retry()
        self.clock.advance(60)
        self.engine.handle('Start', self.params)
        self.assertEqual(self.reads(), 1)
        self.client.hosts = [host(user='')]
        self.clock.advance(5)
        self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')
        self.assertIsNone(self.store.get(self.params['ip'])['error'])

    def test_concurrent_duplicate_missing_events_are_limited_by_cooldown(self):
        self.long_missing_retry()
        self.clock.advance(60)
        for _ in range(3):
            with ThreadPoolExecutor(max_workers=12) as pool:
                list(pool.map(lambda _: self.engine.handle('Start', self.params), range(100)))
            self.clock.advance(5)
        self.assertEqual(self.reads(), 3)
        self.assertEqual(self.client.mutations(), [])

    def test_many_missing_ips_share_host_snapshot(self):
        self.long_missing_retry()
        template = self.store.get(self.params['ip'])
        ips = ['192.0.2.' + str(n) for n in range(10, 110)]
        for ip in ips[1:]:
            self.store.update(ip, lambda old, ip=ip: {**template, 'ip':ip})
        self.clock.advance(60)
        for ip in ips:
            self.engine.handle('Start', {**self.params, 'ip':ip})
        self.assertEqual(self.reads(), 1)
        self.assertEqual(self.client.mutations(), [])

    def test_legacy_row_and_restart_keep_cooldown_and_followup(self):
        self.long_missing_retry()
        # A deployed pre-fix lease has no new presence metadata.
        self.store.update(self.params['ip'], lambda old: {
            k:v for k,v in old.items() if not k.startswith('presence_')})
        self.clock.advance(60)
        self.engine.handle('Start', self.params)
        self.assertEqual(self.reads(), 1)
        self.store.close()
        self.store = StateStore(self.path)
        self.engine = Engine(self.registry, self.store, clock=self.clock)
        self.engine.handle('Start', self.params)
        self.assertEqual(self.reads(), 1)
        self.client.hosts = [host(user='')]
        self.clock.advance(5)
        self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')

    def test_host_arriving_without_another_event_is_discovered_before_backoff(self):
        self.long_missing_retry()
        self.client.hosts = [host(user='')]
        self.clock.advance(5)
        self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')
        self.assertIsNone(self.store.get(self.params['ip'])['error'])

    def test_api_failure_events_keep_backoff(self):
        self.client.fail['ActiveHosts.get'] = KerioError('offline')
        self.engine.handle('Start', self.params)
        for _ in range(10):
            row = self.store.get(self.params['ip'])
            self.clock.advance(row['next_try'] - self.clock())
            self.engine.tick()
        self.clock.advance(60)
        self.client.fail.clear()
        count = len(self.client.calls)
        for _ in range(100):
            self.assertIsNotNone(self.engine.handle('Start', self.params))
        self.assertEqual(len(self.client.calls), count)

    def test_event_just_after_missing_probe_waits_only_remaining_cooldown(self):
        self.long_missing_retry()
        self.clock.advance(1)
        self.client.hosts = [host(user='')]
        self.engine.handle('Start', self.params)
        self.assertEqual(self.reads(), 0)
        self.clock.advance(4)
        self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')

    def test_short_window_ends_when_events_stop(self):
        self.long_missing_retry()
        self.clock.advance(60)
        self.engine.handle('Start', self.params)
        for _ in range(2):
            self.clock.advance(5)
            self.engine.tick()
        self.assertEqual(self.reads(), 3)
        self.clock.advance(299)
        self.engine.tick()
        # One shared discovery read is allowed, but no per-IP retry or write.
        self.assertEqual(self.reads(), 4)
        self.assertEqual(self.client.mutations(), [])

    def test_background_discovery_of_100_missing_hosts_uses_one_snapshot_per_pass(self):
        self.long_missing_retry()
        template = self.store.get(self.params['ip'])
        for n in range(11, 110):
            ip = '192.0.2.' + str(n)
            self.store.update(ip, lambda old, ip=ip: {**template, 'ip':ip})
        self.clock.advance(5)
        before = {r['ip']:r['next_try'] for r in self.store.all()}
        for _ in range(100):
            self.engine.tick()
        self.assertEqual(self.reads(), 1)
        self.assertEqual({r['ip']:r['next_try'] for r in self.store.all()}, before)
        self.clock.advance(5)
        self.engine.tick()
        self.assertEqual(self.reads(), 2)
        self.assertEqual(self.client.mutations(), [])

    def test_background_discovery_does_not_scan_healthy_only_target(self):
        self.engine.handle('Start', self.params)
        self.client.calls.clear()
        for _ in range(10):
            self.clock.advance(5)
            self.engine.tick()
        self.assertEqual(self.client.calls, [])

    def test_discovery_does_not_wake_a_stop_superseding_its_snapshot(self):
        self.long_missing_retry()
        self.clock.advance(5)
        self.client.hosts = [host(user='')]
        original = self.client._exchange
        changed = []
        def exchange(payload, headers):
            if payload['method'] == 'ActiveHosts.get' and not changed:
                changed.append(True)
                self.store.update(self.params['ip'], lambda old: {
                    **old, 'generation':old['generation']+1, 'desired':'stop',
                    'next_try':self.clock()+300, 'error':'logout retry'})
            return original(payload, headers)
        self.client._exchange = exchange
        self.engine.tick()
        self.assertTrue(changed)
        row = self.store.get(self.params['ip'])
        self.assertEqual(row['desired'], 'stop')
        self.assertEqual(row['next_try'], self.clock()+300)
        self.assertEqual(self.client.mutations(), [])

    def test_multi_target_discovery_without_new_event_preserves_ambiguity_guard(self):
        second = Appliance();second.clock = self.clock;second.hosts = []
        self.registry.clients['second'] = second
        self.long_missing_retry()
        self.client.hosts = [host(user='')];second.hosts = [host(user='')]
        self.clock.advance(5)
        self.engine.tick()
        self.assertIn('Ambiguous', self.store.get(self.params['ip'])['error'])
        self.assertEqual(self.client.mutations()+second.mutations(), [])

    def test_discovery_obeys_target_failure_backoff(self):
        self.long_missing_retry()
        self.client._unavailable_until = self.clock()+300
        for _ in range(5):
            self.clock.advance(5)
            self.engine.tick()
        self.assertEqual(self.client.calls, [])
        self.assertEqual(self.client.mutations(), [])

    def test_event_during_background_probe_retains_followup(self):
        self.long_missing_retry()
        self.clock.advance(300)
        original = self.client._exchange
        threads = []
        def exchange(payload, headers):
            if payload['method'] == 'ActiveHosts.get' and not threads:
                self.clock.advance(1)
                t = threading.Thread(target=lambda: self.engine.handle('Start', self.params))
                threads.append(t)
                t.start()
                for _ in range(200):
                    if self.store.get(self.params['ip'])['updated'] == self.clock():
                        break
                    threading.Event().wait(.005)
                self.assertEqual(self.store.get(self.params['ip'])['updated'], self.clock())
            return original(payload, headers)
        self.client._exchange = exchange
        self.engine.tick()
        for t in threads:
            t.join(3)
            self.assertFalse(t.is_alive())
        self.client.hosts = [host(user='')]
        self.clock.advance(5)
        self.engine.tick()
        self.assertEqual(self.client.hosts[0]['user']['name'], 'alice')

    def test_manual_conflict_is_not_accelerated_by_events(self):
        self.client.hosts = [host(user='bob', method='AuthMethodAutomatic')]
        self.engine.handle('Start', self.params)
        for _ in range(10):
            row = self.store.get(self.params['ip'])
            self.clock.advance(row['next_try'] - self.clock())
            self.engine.tick()
        self.clock.advance(60)
        count = len(self.client.calls)
        for _ in range(100):
            self.assertIn('override', self.engine.handle('Start', self.params))
        self.assertEqual(len(self.client.calls), count)
        self.assertEqual(self.client.mutations(), [])
