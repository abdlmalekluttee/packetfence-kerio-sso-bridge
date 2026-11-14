"""Durable, idempotent desired-state reconciliation for PacketFence events."""
import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
from .kerio import KerioError, normalized_user

LOG = logging.getLogger(__name__)


def mac_key(value):
    compact = value.replace(':', '').replace('-', '').lower()
    return compact if re.fullmatch('[0-9a-f]{12}', compact) else value.casefold()


def fingerprint(client):
    return hashlib.sha256(json.dumps(client.cfg, sort_keys=True).encode()).hexdigest()


class Engine:
    def __init__(self, registry, store, clock=time.time, verified_ttl=30, reconcile_interval=60,
                 fallback_ttl=3600):
        self.registry, self.store, self.clock = registry, store, clock
        self.verified_ttl = verified_ttl
        self.reconcile_interval = reconcile_interval
        self.fallback_ttl = fallback_ttl
        self._locks = [threading.Lock() for _ in range(64)]
        self._stop = threading.Event()
        self._worker = None
        self._worker_error = None

    def _validate(self, method, p):
        if method not in ('Start', 'Update', 'Stop'):
            raise ValueError('Unknown method')
        if not isinstance(p, dict):
            raise ValueError('params must be an object')
        for name in ('ip', 'user'):
            value = p.get(name)
            if not isinstance(value, str) or not value.strip() or len(value) > 256 or any(ord(c) < 32 for c in value):
                raise ValueError(f'Invalid {name}')
        ip = str(ipaddress.ip_address(p['ip']))
        mac = p.get('mac', '')
        if not isinstance(mac, str) or len(mac) > 256 or any(ord(c) < 32 for c in mac):
            raise ValueError('Invalid mac/device identity')
        timeout = p.get('timeout', 0)
        if type(timeout) is not int or timeout < 0 or timeout > 10 * 365 * 86400:
            raise ValueError('Invalid timeout')
        return ip, normalized_user(p['user']), mac_key(mac), timeout or self.fallback_ttl

    def handle(self, method, params):
        ip, user, mac, ttl = self._validate(method, params)
        desired = 'stop' if method == 'Stop' else 'active'
        now = self.clock()
        ignored = [False]

        def receive(old):
            same = old and old['user'] == user and (not old['mac'] or not mac or old['mac'] == mac)
            if old and desired == 'stop' and not same:
                ignored[0] = True
                return None
            if same and old['desired'] == desired and not old.get('complete'):
                return {**old, 'expires':now + ttl if desired == 'active' else old['expires'],
                        'updated':now, 'mac':mac or old['mac']}
            return {'ip':ip, 'user':user, 'mac':mac, 'desired':desired,
                    'generation':(old['generation'] + 1) if old else 1,
                    'target':old.get('target') if old else None,
                    'expires':now + ttl, 'verified':0, 'next_try':0, 'attempts':0,
                    'error':None, 'complete':False, 'updated':now, 'config':None}

        record = self.store.update(ip, receive)  # commit before any remote side effect
        if ignored[0]:
            LOG.info('ignored_stale_stop ip=%s', ip)
            return None
        if record['next_try'] > now:
            return record['error'] or 'Synchronization pending'
        return self._reconcile(ip)

    def _current(self, row):
        latest = self.store.get(row['ip'])
        return latest and latest['generation'] == row['generation']

    def _patch(self, row, **changes):
        def update(old):
            return {**old, **changes} if old and old['generation'] == row['generation'] else None
        return self.store.update(row['ip'], update)

    def _select(self, row):
        if row.get('target') is not None:
            client = self.registry.get_client(row['target'])
            if client is None or not client.cfg.get('enabled', True):
                raise KerioError('Assigned Kerio target missing or disabled; restore it to reconcile')
            return row['target'], client
        candidates = self.registry.candidates(row['ip'])
        if not candidates:
            raise KerioError('No configured Kerio target for IP')
        if len(candidates) == 1:
            return candidates[0]
        matches = []
        for eid, client in candidates:
            if client.host_by_ip(row['ip']):
                matches.append((eid, client))
        if len(matches) > 1:
            raise KerioError('Ambiguous Kerio targets; configure non-overlapping subnets')
        if not matches:
            raise KerioError('No active host on configured targets')
        return matches[0]

    def _reconcile(self, ip, force=False):
        lock = self._locks[hash(ip) % len(self._locks)]
        if not lock.acquire(timeout=10):
            return 'Synchronization busy; retry pending'
        try:
            row = self.store.get(ip)
            if not row or row.get('complete'):
                return None
            if row['desired'] == 'active' and row['expires'] <= self.clock():
                row = self._patch(row, desired='stop', generation=row['generation'] + 1, verified=0, next_try=0)
            if row['next_try'] > self.clock():
                return row['error'] or 'Synchronization pending'
            try:
                eid, client = self._select(row)
                cfg = fingerprint(client)
                if (not force and row['desired'] == 'active' and row['verified']
                        and self.clock() - row['verified'] < self.verified_ttl and row['config'] == cfg):
                    return None
                self._patch(row, target=eid)
                with client.transaction():
                    host = client.host_by_ip(ip, fresh=force or bool(row['verified']) or row['desired'] == 'stop')
                    if not self._current(row):
                        return 'Superseded; latest event pending'
                    expected = client.user_name(row['user'])
                    if row['desired'] == 'stop':
                        if host and client.matches(host, expected) and self._mac_matches(row, host):
                            client.logout(host['id'])
                            check = client.host_by_ip(ip, fresh=True)
                            if check and client.matches(check, expected):
                                raise KerioError('Logout verification failed')
                        self._patch(row, complete=True, error=None, attempts=0, next_try=0,
                                    verified=self.clock(), updated=self.clock())
                        return None
                    if host is None:
                        raise KerioError('Host not yet present in Kerio; retry pending')
                    if not self._mac_matches(row, host):
                        raise KerioError('PacketFence and Kerio MAC differ; refusing stale IP binding')
                    if not client.matches(host, expected):
                        # Mutations always start from a fresh snapshot, even if selection used the cache.
                        host = client.host_by_ip(ip, fresh=True)
                        if host is None or not self._mac_matches(row, host):
                            raise KerioError('Host changed before bind; retry pending')
                        if not client.matches(host, expected):
                            client.prepare_conflict(host, ip, expected)
                            if not self._current(row):
                                return 'Superseded; latest event pending'
                            # Configuration inspection may take time. Re-read before logout.
                            current = client.host_by_ip(ip, fresh=True)
                            if current is None or current.get('id') != host.get('id') or not self._mac_matches(row,current):
                                raise KerioError('Host changed before mutation')
                            if not client.matches(current, expected):
                                if current.get('user') != host.get('user'):
                                    raise KerioError('Kerio owner changed concurrently; retry pending')
                                if (current.get('user') or {}).get('name'):
                                    client.logout(current['id'])
                                if not self._current(row):
                                    return 'Superseded; latest event pending'
                                client.login_user(current['id'], expected)
                                verified = client.host_by_ip(ip, fresh=True)
                                if not verified or not client.matches(verified, expected):
                                    raise KerioError('Login verification failed')
                    self._patch(row, verified=self.clock(), config=cfg, target=eid,
                                error=None, attempts=0, next_try=0)
                    return None if self._current(row) else 'Superseded; latest event pending'
            except Exception as ex:
                # Only controlled API errors reach clients; no secrets from arbitrary exceptions.
                error = str(ex) if isinstance(ex, KerioError) else f'Synchronization failed ({type(ex).__name__})'
                attempts = row['attempts'] + 1
                self._patch(row, error=error, attempts=attempts,
                            next_try=self.clock() + min(300, 2 ** min(attempts, 9)))
                LOG.warning('sync_pending ip=%s reason=%s', ip, error)
                return error
        finally:
            lock.release()

    @staticmethod
    def _mac_matches(row, host):
        actual = mac_key(host.get('macAddress') or '')
        wanted = row['mac']
        # VPN device identity may be a username, not a MAC. Compare only real MACs.
        return not (re.fullmatch('[0-9a-f]{12}', wanted or '') and
                    re.fullmatch('[0-9a-f]{12}', actual or '') and wanted != actual)

    def tick(self):
        now = self.clock()
        for row in self.store.all():
            if self._stop.is_set():
                break
            expired = row['desired'] == 'active' and row['expires'] <= now
            if not row.get('complete') and (expired or (row['next_try'] <= now and
                    (row['error'] or not row['verified'] or now-row['verified'] >= self.reconcile_interval))):
                self._reconcile(row['ip'], force=True)
        self.store.prune(now - 3600)

    def status(self):
        rows = self.store.all()
        return {'active':sum(r['desired']=='active' and not r['complete'] for r in rows),
                'pending':sum(bool(r['error']) and not r['complete'] for r in rows),
                'worker_error':self._worker_error,
                'leases':[{'ip':r['ip'],'user':r['user'],'target':r['target'],'desired':r['desired'],
                           'expires':r['expires'],'error':r['error']} for r in rows if not r['complete']][:200]}

    def start(self):
        def run():
            while not self._stop.is_set():
                try:
                    self.tick(); self._worker_error = None
                except Exception as ex:
                    self._worker_error = type(ex).__name__
                    LOG.error('reconciliation_worker_error type=%s', type(ex).__name__)
                self._stop.wait(1)
        self._worker = threading.Thread(target=run, name='sso-reconcile', daemon=True)
        self._worker.start()

    def close(self):
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=30)
