#!/usr/bin/env bash
# Start a throwaway Forgejo for `ag1 --service forgejo` and print the two
# environment variables the harness reads. The admin token is the broad service
# credential the enforcement point uses; keep it out of logs.
#
#   eval "$(scripts/forgejo-up.sh)"
#
# Environment: AG1_FORGEJO_PORT (default 3300), AG1_FORGEJO_CONTAINER (default ag1-forgejo).
set -euo pipefail

IMAGE="codeberg.org/forgejo/forgejo:16.0.6@sha256:e2c34a699543ca8a00217ee9ab2bea5feedc98bd6d0ea95ec287d3b7ae1355c6"
PORT="${AG1_FORGEJO_PORT:-3300}"
NAME="${AG1_FORGEJO_CONTAINER:-ag1-forgejo}"
URL="http://localhost:${PORT}"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:3000" \
  -e FORGEJO__security__INSTALL_LOCK=true \
  -e FORGEJO__database__DB_TYPE=sqlite3 \
  -e FORGEJO__server__ROOT_URL="${URL}/" \
  -e FORGEJO__service__DISABLE_REGISTRATION=true \
  "$IMAGE" >/dev/null

for _ in $(seq 120); do
  curl -sf "${URL}/api/v1/version" >/dev/null && break
  sleep 1
done
curl -sf "${URL}/api/v1/version" >/dev/null || { echo "Forgejo did not start" >&2; exit 1; }

PASSWORD="$(openssl rand -hex 16)"
docker exec -u git "$NAME" forgejo admin user create --admin --username ag1-service \
  --password "$PASSWORD" --email ag1-service@example.invalid --must-change-password=false >/dev/null
TOKEN="$(docker exec -u git "$NAME" forgejo admin user generate-access-token \
  --username ag1-service --token-name ag1 --scopes all --raw)"

echo "export AG1_FORGEJO_URL=${URL}"
echo "export AG1_FORGEJO_TOKEN=${TOKEN}"
