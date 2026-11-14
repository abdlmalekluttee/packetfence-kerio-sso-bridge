#!/usr/bin/env bash
# Local build/install. Does not modify Kerio; configured policy acts on SSO events.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
for command in python3 openssl docker; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done
docker compose version >/dev/null
python3 configure.py
mkdir -p certs data
chmod 700 certs data
if [ ! -f certs/bridge.crt ] || [ ! -f certs/bridge.key ]; then
  HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  HOST_IP="${HOST_IP:-127.0.0.1}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout certs/bridge.key -out certs/bridge.crt \
    -days 365 -subj "/CN=PacketFence Kerio SSO Bridge" \
    -addext "subjectAltName=IP:${HOST_IP}" >/dev/null 2>&1
fi
chown -R 10001:10001 certs data
chmod 600 .env certs/bridge.key
find data -type f -exec chmod 600 {} +
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 90
echo 'Bridge is healthy. Open https://<bridge-host>:<HOST_PORT or 9090>/ .'
echo 'Read docs/operations.md for migration, TLS trust and live acceptance tests.'
