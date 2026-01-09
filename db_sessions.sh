#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source .env

mariadb -u "$CROW_DB_USER" -p"$CROW_DB_PASS" -h "$CROW_DB_HOST" -D "$CROW_DB_NAME" \
  -e "SELECT sid,user_id,expires_at,created_at FROM sessions ORDER BY created_at DESC LIMIT 10;"
