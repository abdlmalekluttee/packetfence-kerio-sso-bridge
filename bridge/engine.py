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
HOST_MISSING = 'Host not yet present in Kerio; retry pending'
MISSING_HOST_ERRORS = (HOST_MISSING, 'No active host on configured targets')
PRESENCE_COOLDOWN = 5
PRESENCE_WINDOW = 10
SOURCE_STALE = 'PacketFence binding obsolete; preserving any existing Kerio session'
SOURCE_UNKNOWN = 'PacketFence ownership unverified; preserving existing Kerio sessions'
RECOVERY_WAIT = 'Exact IP override verified; recovery settling'


def usable_ip(value):
    address = ipaddress.ip_address(value)
    address = getattr(address, 'ipv4_mapped', None) or address
    return not (address.is_link_local or address.is_loopback or address.is_unspecified
                or address.is_multicast or str(address) == '255.255.255.255')


def mac_key(value):
    compact = value.replace(':', '').replace('-', '').lower()
    return compact if re.fullmatch('[0-9a-f]{12}', compact) else value.casefold()


def fingerprint(client):
    return hashlib.sha256(json.dumps(client.cfg, sort_keys=True).encode()).hexdigest()


class Engine:
    def __init__(self, registry, store, clock=time.time, verified_ttl=30, reconcile_interval=60,
                 fallback_ttl=3600, source=None):
        self.registry, self.store, self.clock = registry, store, clock
        self.verified_ttl = verified_ttl
        self.reconcile_interval = reconcile_interval
        self.fallback_ttl = fallback_ttl
        self._locks = [threading.Lock() for _ in range(64)]
        self._stop = threading.Event()
        self._worker = None
        self._worker_error = None
        self._presence_scans = {}
        self.source = source

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
        # Resolve formatting before entering the state transaction: registry edits
        # use registry -> state lock order, never the reverse.
        prior = self.store.get(ip)
        if not usable_ip(ip):
            if prior:
                self._ignore(prior)
            return None
        if self.registry.ignores_user(user):
            if prior and self.registry.ignores_user(prior['user']):
                self._ignore(prior)
            return None
        retired = prior and prior.get('complete') and prior['desired'] == 'ignored'
        identity_target = prior.get('target') if prior and not retired else None
        identity_client = self.registry.get_client(identity_target) if identity_target is not None else None
        if identity_target is None:
            candidates = self.registry.candidates(ip, user)
            if len(candidates) == 1:
                identity_target, identity_client = candidates[0]

        def receive(old):
            old_target = old.get('target') if old and not (old.get('complete') and old['desired']=='ignored') else None
            same_user = old and old['user'] == user
            if old and identity_client and old_target in (None, identity_target):
                same_user = identity_client.user_name(old['user']) == identity_client.user_name(user)
            same = old and same_user and (not old['mac'] or not mac or old['mac'] == mac)
            if old and desired == 'stop' and not same:
                ignored[0] = True
                return None
            if same and old['desired'] == desired and not old.get('complete'):
                renewed = {**old, 'expires':now + ttl if desired == 'active' else old['expires'],
                           'updated':now, 'mac':mac or old['mac'], 'source_stale_since':None}
                if desired == 'active':
                    renewed['presence_until'] = now + PRESENCE_WINDOW
                    if old.get('error') in MISSING_HOST_ERRORS:
                        # An event is a presence hint, not proof of a new session.
                        # Coalesce concurrent hints using durable per-IP timing.
                        renewed['next_try'] = min(old['next_try'],
                            max(now, old.get('presence_retry_after', 0)))
                return renewed
            return {'ip':ip, 'user':user, 'mac':mac, 'desired':desired,
                    'generation':(old['generation'] + 1) if old else 1,
                    'target':old_target,
                    'expires':now + ttl, 'verified':0, 'next_try':0, 'attempts':0,
                    'error':None, 'complete':False, 'updated':now, 'config':None,
                    'presence_until':now + PRESENCE_WINDOW if desired == 'active' else 0}

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
            if not client.accepts_user(row['user']):
                raise KerioError('Assigned Kerio target does not serve this domain; controlled migration required')
            return row['target'], client
        candidates = self.registry.candidates(row['ip'], row['user'])
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

    def _ignore(self, row):
        self._patch(row, desired='ignored', complete=True, error=None, attempts=0,
                    next_try=0, updated=self.clock(), generation=row['generation'] + 1)

    def _reconcile(self, ip, force=False):
        lock = self._locks[hash(ip) % len(self._locks)]
        if not lock.acquire(timeout=10):
            return 'Synchronization busy; retry pending'
        try:
            row = self.store.get(ip)
            if not row or row.get('complete'):
                return None
            if not usable_ip(ip) or self.registry.ignores_user(row['user']):
                self._ignore(row)
                return None
            if row['desired'] == 'active' and row['expires'] <= self.clock():
                def expire(latest):
                    if (latest and latest['generation'] == row['generation']
                            and latest['desired'] == 'active' and latest['expires'] <= self.clock()):
                        return {**latest, 'desired':'stop', 'generation':latest['generation'] + 1,
                                'verified':0, 'next_try':0}
                    return None
                row = self.store.update(ip, expire)
                if not row or row.get('complete'):
                    return None
            if row['next_try'] > self.clock():
                return row['error'] or 'Synchronization pending'
            try:
                eid, client = self._select(row)
                with self.registry.operation(eid, expected=client, pin=lambda: self._patch(row, target=eid)), client.transaction():
                    cfg = fingerprint(client)
                    if (not force and row['desired'] == 'active' and row['verified']
                            and self.clock() - row['verified'] < self.verified_ttl and row['config'] == cfg):
                        return None
                    if self.source:
                        source_error = self._check_source(row, client)
                        if source_error:
                            return source_error
                    host = client.host_by_ip(ip, fresh=row['desired'] == 'stop')
                    if not self._current(row):
                        return 'Superseded; latest event pending'
                    expected = client.user_name(row['user'])
                    if row['desired'] == 'stop':
                        siblings = self._siblings(row, eid, host) if host else []
                        protected = any(client.user_name(other['user']) == expected and self._mac_matches(other, host)
                                        for other in siblings)
                        if host and not protected and client.matches(host, expected) and self._mac_matches(row, host):
                            client.logout(host['id'])
                            check = client.host_by_ip(ip, fresh=True)
                            if check and client.matches(check, expected):
                                raise KerioError('Logout verification failed')
                        self._patch(row, complete=True, error=None, attempts=0, next_try=0,
                                    verified=self.clock(), updated=self.clock())
                        return None
                    if host is None:
                        raise KerioError(HOST_MISSING)
                    if not self._mac_matches(row, host):
                        raise KerioError('PacketFence and Kerio MAC differ; refusing stale IP binding')
                    if not client.matches(host, expected):
                        # Mutations always start from a fresh snapshot, even if selection used the cache.
                        host = client.host_by_ip(ip, fresh=True)
                        if host is None or not self._mac_matches(row, host):
                            raise KerioError('Host changed before bind; retry pending')
                        if not client.matches(host, expected):
                            if any(client.user_name(other['user']) != expected for other in self._siblings(row, eid, host)):
                                raise KerioError('Conflicting active identities share this Kerio host; resolve alias leases')
                            recovery=row.get('manual_recovery')
                            if recovery and (recovery.get('config')!=cfg or recovery.get('expires',0)<=self.clock()
                                    or recovery.get('binds',0)>=2):
                                raise KerioError('Manual override recovery expired, changed or exhausted; refusing mutation')
                            def checkpoint(proof):
                                written=[False]
                                def save(latest):
                                    if not latest or latest['generation']!=row['generation']:
                                        return None
                                    prior=latest.get('manual_recovery') or {}
                                    writes=prior.get('writes',0)+(proof['phase']=='prepared')
                                    if writes>2:
                                        raise KerioError('Manual override write limit reached; refusing mutation')
                                    value={**proof,'config':cfg,'writes':writes,'binds':prior.get('binds',0),
                                           'expires':prior.get('expires',self.clock()+900),
                                           'not_before':max(prior.get('not_before',0),self.clock()+5)}
                                    written[0]=True
                                    return {**latest,'manual_recovery':value}
                                self.store.update(ip,save)
                                return written[0]
                            client.prepare_conflict(host, ip, expected, recovery, checkpoint)
                            if not self._current(row):
                                return 'Superseded; latest event pending'
                            recovery=self.store.get(ip).get('manual_recovery')
                            if recovery and recovery['not_before']>self.clock():
                                self._patch(row,error=RECOVERY_WAIT,next_try=recovery['not_before'])
                                return RECOVERY_WAIT
                            # Configuration inspection may take time. Re-read before logout.
                            current = client.host_by_ip(ip, fresh=True)
                            if current is None or current.get('id') != host.get('id') or not self._mac_matches(row,current):
                                raise KerioError('Host changed before mutation')
                            if not client.matches(current, expected):
                                if current.get('user') != host.get('user'):
                                    raise KerioError('Kerio owner changed concurrently; retry pending')
                                if recovery:
                                    reserved=[False]
                                    def reserve(latest):
                                        if not latest or latest['generation']!=row['generation']:
                                            return None
                                        proof=latest.get('manual_recovery')
                                        if (not proof or proof['expires']<=self.clock() or proof['binds']>=2
                                                or proof['not_before']>self.clock()):
                                            raise KerioError('Manual override recovery not eligible; refusing mutation')
                                        reserved[0]=True
                                        return {**latest,'manual_recovery':{**proof,'binds':proof['binds']+1,
                                                                                 'not_before':self.clock()+60}}
                                    self.store.update(ip,reserve)
                                    if not reserved[0]:
                                        return 'Superseded; latest event pending'
                                if (current.get('user') or {}).get('name'):
                                    client.logout(current['id'])
                                if not self._current(row):
                                    return 'Superseded; latest event pending'
                                after=client.host_by_ip(ip,fresh=True)
                                if not self._current(row):
                                    return 'Superseded; latest event pending'
                                if (not after or after.get('id')!=current['id'] or not self._mac_matches(row,after)):
                                    raise KerioError('Host changed after logout; retry safely')
                                if not client.matches(after,expected):
                                    if (after.get('user') or {}).get('name'):
                                        raise KerioError('Host authenticated again after logout; recovery pending')
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
                def failed(latest):
                    if not latest or latest['generation'] != row['generation']:
                        return None
                    now = self.clock()
                    changes = {'error':error, 'attempts':attempts,
                               'next_try':now + min(300, 2 ** min(attempts, 9))}
                    if latest.get('manual_recovery'):
                        changes['next_try']=max(changes['next_try'],latest['manual_recovery'].get('not_before',0))
                    if error in MISSING_HOST_ERRORS and latest['desired'] == 'active':
                        changes['presence_retry_after'] = now + PRESENCE_COOLDOWN
                        # Read the latest event deadline inside the transaction:
                        # an event can arrive while the Kerio read is in flight.
                        if latest.get('presence_until', 0) > now:
                            changes['next_try'] = now + PRESENCE_COOLDOWN
                    return {**latest, **changes}
                self.store.update(row['ip'], failed)
                LOG.warning('sync_pending ip=%s reason=%s', ip, error)
                return error
        finally:
            lock.release()

    def _check_source(self, row, client):
        authority, observed = self.source.assess(row, client.user_name)
        if authority == 'current':
            self._patch(row, source_stale_since=None)
            return None
        error = SOURCE_STALE if authority == 'stale' else SOURCE_UNKNOWN
        since = row.get('source_stale_since')
        retire = False
        if authority == 'stale':
            since = max(since if since is not None else observed, row['updated'])
            if observed - since >= 60:
                # Do not logout even idle hosts: routed MACs and PF history can disagree.
                retire = client.host_by_ip(row['ip'], fresh=True) is None
        else:
            since = None
        def update(latest):
            if (not latest or latest['generation'] != row['generation']
                    or latest['updated'] != row['updated']):
                return None
            if retire:
                return {**latest, 'desired':'ignored', 'complete':True, 'error':None,
                        'generation':latest['generation']+1, 'updated':self.clock(),
                        'next_try':0, 'attempts':0, 'retired_reason':'obsolete_packetfence_binding'}
            return {**latest, 'error':error, 'next_try':self.clock()+60,
                    'attempts':0, 'source_stale_since':since, 'source_seen':observed}
        result = self.store.update(row['ip'], update)
        if retire and result.get('complete'):
            LOG.info('retired_obsolete_binding ip=%s', row['ip'])
            return 'Obsolete PacketFence binding retired'
        return error

    def _siblings(self, row, eid, host):
        """Kerio login/logout affect every IP alias of the resolved host."""
        siblings = []
        for value in [host.get('ip')] + (host.get('ip6Addresses') or []):
            try:
                ip = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if ip == row['ip']:
                continue
            other = self.store.get(ip)
            if (other and other.get('target') == eid and not other.get('complete')
                    and other['desired'] == 'active' and other['expires'] > self.clock()):
                siblings.append(other)
        return siblings

    @staticmethod
    def _mac_matches(row, host):
        actual = mac_key(host.get('macAddress') or '')
        wanted = row['mac']
        # VPN device identity may be a username, not a MAC. Compare only real MACs.
        return not (re.fullmatch('[0-9a-f]{12}', wanted or '') and
                    re.fullmatch('[0-9a-f]{12}', actual or '') and wanted != actual)

    def _discover_hosts(self, now):
        groups = {}
        for row in self.store.all():
            if (row.get('complete') or row['desired'] != 'active' or row['expires'] <= now
                    or row.get('error') not in MISSING_HOST_ERRORS):
                continue
            target = row.get('target')
            candidates = ([(target, self.registry.get_client(target))] if target is not None
                          else self.registry.candidates(row['ip'], row['user']))
            for eid, client in candidates:
                if client and client.cfg.get('enabled', True) and client.accepts_user(row['user']):
                    groups.setdefault(eid, (client, []))[1].append(row)
        self._presence_scans = {eid:due for eid,due in self._presence_scans.items() if eid in groups}
        for eid, (client, rows) in groups.items():
            if self._stop.is_set():
                break
            if self._presence_scans.get(eid, 0) > self.clock():
                continue
            self._presence_scans[eid] = self.clock() + PRESENCE_COOLDOWN
            try:
                with self.registry.operation(eid, expected=client), client.transaction():
                    present = client.present_ips([row['ip'] for row in rows])
            except KerioError:
                # Client-wide outage backoff still gates all network calls.
                continue
            for row in rows:
                if row['ip'] not in present:
                    continue
                def wake(latest):
                    if (latest and latest['generation'] == row['generation']
                            and not latest.get('complete') and latest['desired'] == 'active'
                            and latest['expires'] > self.clock()
                            and latest.get('error') in MISSING_HOST_ERRORS):
                        return {**latest, 'next_try':0}
                    return None
                self.store.update(row['ip'], wake)

    def tick(self):
        now = self.clock()
        if self.source:
            self.source.refresh([r for r in self.store.all() if not r.get('complete') and usable_ip(r['ip'])])
            for row in self.store.all():
                if (not row.get('complete') and row.get('error') in (SOURCE_STALE,SOURCE_UNKNOWN)
                        and self.source.observed(row['ip']) > row.get('source_seen',0)):
                    self._patch(row,next_try=0)
        self._discover_hosts(now)
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
        pending = [r for r in rows if r['error'] and not r['complete']]
        waiting = sum(r['error'] in MISSING_HOST_ERRORS for r in pending)
        held = sum(r['error'] in (SOURCE_STALE, SOURCE_UNKNOWN) for r in pending)
        return {'active':sum(r['desired']=='active' and not r['complete'] for r in rows),
                'pending':len(pending), 'waiting':waiting, 'held':held, 'failed':len(pending)-waiting-held,
                'source_error':self.source.error if self.source else None,
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
