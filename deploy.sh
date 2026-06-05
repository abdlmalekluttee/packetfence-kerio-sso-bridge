#!/usr/bin/env bash
#
# deploy.sh - one-shot deployment for the PacketFence -> Kerio SSO bridge.
# Prompts ONLY for usernames/passwords; does everything else automatically:
#   writes .env, generates a self-signed TLS cert, fixes permissions,
#   builds the image, and starts the container.
#
set -euo pipefail
cd "$(dirname "$0")"

echo "=============================================="
echo " PacketFence -> Kerio Control SSO Bridge setup"
echo "=============================================="
echo "(passwords must NOT contain spaces)"
echo

# ---- the only interactive part: credentials ----
read -rp  "GUI admin username [admin]: " ADMIN_USER; ADMIN_USER=${ADMIN_USER:-admin}
read -rsp "GUI admin password: " ADMIN_PASS; echo
read -rp  "PacketFence (bridge) username [packetfence]: " BRIDGE_USER; BRIDGE_USER=${BRIDGE_USER:-packetfence}
read -rsp "PacketFence (bridge) password: " BRIDGE_PASS; echo
echo

if [ -z "$ADMIN_PASS" ] || [ -z "$BRIDGE_PASS" ]; then
  echo "ERROR: passwords cannot be empty." >&2
  exit 1
fi
case "$ADMIN_PASS$BRIDGE_PASS" in
  *" "*) echo "ERROR: passwords must not contain spaces." >&2; exit 1 ;;
esac

# ---- everything below is automatic ----
mkdir -p certs data

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
HOST_IP="${HOST_IP:-127.0.0.1}"

cat > .env <<EOF
BRIDGE_USER=${BRIDGE_USER}
BRIDGE_PASS=${BRIDGE_PASS}
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
LISTEN_ADDR=0.0.0.0
LISTEN_PORT=9090
CERT_FILE=/certs/bridge.crt
KEY_FILE=/certs/bridge.key
EOF
chmod 600 .env

if [ ! -f certs/bridge.crt ] || [ ! -f certs/bridge.key ]; then
  echo "Generating self-signed certificate (CN=${HOST_IP}) ..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout certs/bridge.key -out certs/bridge.crt \
    -days 825 -subj "/CN=${HOST_IP}" >/dev/null 2>&1
fi

# the container runs as uid 10001 and must read the cert/key and write data/
chown -R 10001:10001 certs data 2>/dev/null || sudo chown -R 10001:10001 certs data

echo "Building and starting the container ..."
if docker compose version >/dev/null 2>&1; then
  docker compose up -d --build
else
  docker-compose up -d --build
fi

echo
echo "=============================================="
echo " Done."
echo " GUI:   https://${HOST_IP}:9090/"
echo " Login: ${ADMIN_USER}"
echo " PacketFence JSONRPC firewall -> host ${HOST_IP}, port 9090,"
echo "        user ${BRIDGE_USER} (+ the password you set)"
echo "=============================================="
