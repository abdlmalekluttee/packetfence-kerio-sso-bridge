"""Validated target configuration with atomic disk and memory publication."""
import copy
import ipaddress
import json
import os
import re
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from .kerio import KerioClient, KerioError


def full_domain(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError('Domain must be a full DNS domain')
    value = value.strip().casefold()
    labels = value.split('.')
    if len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in labels):
        raise ValueError('Domain must be a full DNS domain')
    return value


class Registry:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.RLock()
        # Stable across client replacements/deletion; bounded even with ID churn.
        self._operations = [threading.RLock() for _ in range(64)]
        self._entries = {}
        self._clients = {}
        if self.path.exists():
            try:
                rows = json.loads(self.path.read_text(encoding='utf-8'))
                if not isinstance(rows, list) or len(rows) > 64:
                    raise ValueError('Configuration must be a list of at most 64 targets')
                for row in rows:
                    entry = self._validate(row, {})
                    if entry['id'] in self._entries:
                        raise ValueError('Duplicate target ID')
                    self._entries[entry['id']] = entry
                self._clients = {i:KerioClient(e) for i,e in self._entries.items()}
                os.chmod(self.path, 0o600)
            except (ValueError, TypeError, KeyError) as ex:
                raise ValueError('Invalid Kerio configuration; restore a valid backup') from ex

    def _validate(self, data, existing):
        if not isinstance(data, dict):
            raise ValueError('Target must be an object')
        values = {**existing, **data}
        entry = {}
        for field, default in (('id',uuid.uuid4().hex),('name',''),('host',''),('user',''),
                               ('prefix',''),('suffix',''),('default_domain',''),('ca_file','')):
            value = values.get(field, default)
            if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 32 for c in value):
                raise ValueError(f'Invalid {field}')
            entry[field] = value.strip()
        entry['id'] = entry['id'] or uuid.uuid4().hex
        if not re.fullmatch('[A-Za-z0-9_-]{1,64}', entry['id']):
            raise ValueError('Invalid target ID')
        entry['name'] = entry['name'] or entry['id']
        host = entry['host'].strip('[]')
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
                raise ValueError('Host must be a hostname or IP without URL/path/userinfo')
        entry['host'] = host
        try:
            port = values.get('port', 4081)
            if isinstance(port, bool) or not str(port).isdigit():
                raise ValueError()
            entry['port'] = int(port)
            if not 1 <= entry['port'] <= 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError('Invalid port') from None
        for field, default in (('verify',True),('enabled',True),('override_manual',False)):
            value = values.get(field, default)
            if type(value) is not bool:
                raise ValueError(f'{field} must be boolean')
            entry[field] = value
        password = data.get('password') or existing.get('password', '')
        if not isinstance(password, str) or not password or len(password) > 1024 or not entry['user']:
            raise ValueError('API user and password are required')
        entry['password'] = password
        subnets = values.get('subnets', [])
        if not isinstance(subnets, list) or len(subnets) > 64 or any(not isinstance(s,str) for s in subnets):
            raise ValueError('Subnets must be a list of CIDRs')
        entry['subnets'] = [str(ipaddress.ip_network(s, strict=False)) for s in subnets]
        aliases = values.get('domain_aliases', {})
        if not isinstance(aliases, dict) or len(aliases) > 64:
            raise ValueError('Domain aliases must be an object of at most 64 mappings')
        entry['domain_aliases'] = {}
        for short, domain in aliases.items():
            if not isinstance(short, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}', short):
                raise ValueError('Alias must be a short realm name')
            short = short.casefold()
            if short == 'local' or short in entry['domain_aliases']:
                raise ValueError('Duplicate or reserved domain alias')
            entry['domain_aliases'][short] = full_domain(domain)
        domains = values.get('domains', [])
        if not isinstance(domains, list) or len(domains) > 64:
            raise ValueError('Domains must be a list of at most 64 domain names')
        entry['domains'] = sorted(set('local' if isinstance(d,str) and d.casefold() == 'local'
                                      else full_domain(d) for d in domains))
        return entry

    def _save(self, entries):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        temp = self.path.with_name(self.path.name + '.' + uuid.uuid4().hex + '.tmp')
        try:
            fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                json.dump(list(entries.values()), out, indent=2)
                out.flush(); os.fsync(out.fileno())
            os.replace(temp, self.path)
        finally:
            if temp.exists():
                temp.unlink()

    @contextmanager
    def operation(self, eid, expected=None, pin=None):
        lock = self._operations[hash(eid) % len(self._operations)]
        if not lock.acquire(timeout=10):
            raise KerioError('Target operation busy; retry pending')
        try:
            with self._lock:
                client = self._clients.get(eid)
                if expected is not None and client is not expected:
                    raise KerioError('Target configuration changed; retry pending')
                if pin is not None:
                    pin()  # Durable binding and configuration publication are atomic locally.
            yield client
        finally:
            lock.release()

    def upsert(self, data, guard=None):
        if not isinstance(data, dict):
            raise ValueError('Target must be an object')
        eid = data.get('id') or uuid.uuid4().hex
        if not isinstance(eid, str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}', eid):
            raise ValueError('Invalid target ID')
        with self.operation(eid), self._lock:
            existing = self._entries.get(eid, {})
            entry = self._validate({**data, 'id':eid}, existing)
            if guard is not None:
                guard(existing, entry)
            entries = {**self._entries, entry['id']:entry}
            if len(entries) > 64:
                raise ValueError('Too many Kerio targets')
            client = self._clients.get(entry['id']) if entry == existing else KerioClient(entry)
            self._save(entries)
            self._entries = entries
            self._clients = {**self._clients, entry['id']:client}
            return entry['id']

    def proposed(self, data):
        with self._lock:
            if not isinstance(data, dict) or not isinstance(data.get('id',''),str):
                raise ValueError('Invalid target object/ID')
            return self._validate(data, self._entries.get(data.get('id'),{}))

    def delete(self, eid, guard=None):
        if not isinstance(eid, str):
            raise ValueError('Invalid target ID')
        with self.operation(eid), self._lock:
            if guard is not None:
                guard(self._entries.get(eid, {'id':eid}), None)
            entries = {i:e for i,e in self._entries.items() if i != eid}
            self._save(entries)
            self._entries = entries
            self._clients = {i:c for i,c in self._clients.items() if i != eid}

    def public_list(self):
        with self._lock:
            return [{**{k:copy.deepcopy(v) for k,v in e.items() if k != 'password'},
                     'hasPassword':bool(e['password'])} for e in self._entries.values()]

    def get_client(self, eid):
        with self._lock:
            return self._clients.get(eid)

    def ignores_user(self, user):
        with self._lock:
            # A disabled target still owns its domains: its events stay pending.
            return bool(self._clients) and not any(c.accepts_user(user) for c in self._clients.values())

    def candidates(self, ip, user=None):
        addr = ipaddress.ip_address(ip)
        with self._lock:
            return [(i,self._clients[i]) for i,e in self._entries.items() if e['enabled'] and
                    (user is None or self._clients[i].accepts_user(user)) and
                    (not e['subnets'] or any(addr in ipaddress.ip_network(s) for s in e['subnets']))]
