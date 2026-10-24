#!/usr/bin/env bash
# Start compose mode from scratch: Forgejo, its two service tokens, then every other service.
#
# The admin token (used by the enforcement points and, to reset and inspect the
# repositories, the driver) and the read-only token (used by the test service) are
# written to .compose-secrets/ and reach containers only as Docker secrets.
set -euo pipefail
cd "$(dirname "$0")/.."

SECRETS=.compose-secrets
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf "$SECRETS"
mkdir -m 700 "$SECRETS"
: > "$SECRETS/forgejo-admin-token"
: > "$SECRETS/forgejo-read-token"

docker compose up -d --wait forgejo

forgejo() { docker compose exec -T -u git forgejo forgejo admin user "$@"; }
forgejo create --admin --username ag1-service --password "$(openssl rand -hex 16)" \
  --email ag1-service@example.invalid --must-change-password=false >/dev/null
forgejo generate-access-token --username ag1-service --token-name ag1 --scopes all --raw \
  > "$SECRETS/forgejo-admin-token"
forgejo create --username ag1-test-service --password "$(openssl rand -hex 16)" \
  --email ag1-test-service@example.invalid --must-change-password=false >/dev/null
forgejo generate-access-token --username ag1-test-service --token-name ag1-tests --scopes read:repository --raw \
  > "$SECRETS/forgejo-read-token"
# Readable by the unprivileged container user; the directory stays private on the host.
chmod 644 "$SECRETS"/*

# The driver runs as an unprivileged user and writes here.
mkdir -p results-compose
chmod 777 results-compose
docker compose up -d --wait --build
echo "ready: docker compose run --rm driver"
