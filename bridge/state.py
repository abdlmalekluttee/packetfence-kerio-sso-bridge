"""Bounded durable desired state; JSON values are never shared with callers."""
import json
import os
import sqlite3
import threading
from pathlib import Path


class StateStore:
    def __init__(self, path, limit=10000):
        self.limit = limit
        self._lock = threading.RLock()
        directory = Path(path).parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600); os.close(fd)
        os.chmod(path, 0o600)
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=5)
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('PRAGMA synchronous=FULL')
        self._db.execute('CREATE TABLE IF NOT EXISTS leases (ip TEXT PRIMARY KEY, data TEXT NOT NULL)')
        self._db.commit()

    def get(self, ip):
        with self._lock:
            row = self._db.execute('SELECT data FROM leases WHERE ip=?', (ip,)).fetchone()
            return json.loads(row[0]) if row else None

    def update(self, ip, transform):
        with self._lock, self._db:
            old = self.get(ip)
            new = transform(old)
            if new is None:
                return old
            if old is None and self._db.execute('SELECT COUNT(*) FROM leases').fetchone()[0] >= self.limit:
                raise RuntimeError('State capacity reached; investigate pending leases')
            self._db.execute('INSERT INTO leases(ip,data) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET data=excluded.data',
                             (ip, json.dumps(new, separators=(',', ':'))))
            return new

    def all(self):
        with self._lock:
            return [json.loads(row[0]) for row in self._db.execute('SELECT data FROM leases')]

    def prune(self, before):
        with self._lock, self._db:
            for row in self.all():
                if row.get('complete') and row['updated'] < before:
                    self._db.execute('DELETE FROM leases WHERE ip=?', (row['ip'],))

    def close(self):
        with self._lock:
            self._db.close()
