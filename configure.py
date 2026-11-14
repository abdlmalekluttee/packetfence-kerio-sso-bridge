#!/usr/bin/env python3
"""Create a new Compose dotenv file without shell interpolation or secret output."""
import getpass
import json
import os
from pathlib import Path


def dotenv_value(value):
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        raise ValueError('Configuration values cannot contain control characters')
    return json.dumps(value, ensure_ascii=False).replace('$', '$$')


def write_env(path, values):
    payload = ''.join(f'{key}={dotenv_value(value)}\n' for key,value in values.items())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        out.write(payload)
        out.flush(); os.fsync(out.fileno())


def main():
    path = Path('.env')
    if path.exists():
        print('Existing .env preserved. Review migration notes before upgrading.')
        return
    values = {}
    for prefix, default in (('ADMIN','admin'),('BRIDGE','packetfence')):
        values[prefix+'_USER'] = input(f'{prefix} username [{default}]: ').strip() or default
        password = getpass.getpass(f'{prefix} password: ')
        if not password or password in ('change-me','change-me-too'):
            raise ValueError('Choose a nonempty password other than the example placeholders')
        if password != getpass.getpass('Confirm password: '):
            raise ValueError('Passwords do not match')
        values[prefix+'_PASS'] = password
    values.update(LISTEN_ADDR='0.0.0.0', LISTEN_PORT='9090', CERT_FILE='/certs/bridge.crt',
                  KEY_FILE='/certs/bridge.key', VERIFIED_TTL='30', RECONCILE_INTERVAL='60', FALLBACK_TTL='3600')
    write_env(path,values)
    print('Created protected .env')


if __name__ == '__main__':
    main()
