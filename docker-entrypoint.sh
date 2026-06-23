#!/bin/sh
set -e

cd /var/www/html

# Ensure Twig's cache directory exists and is writable by www-data (Apache user).
mkdir -p tmp/cache
chmod 777 tmp/cache

# Sync PHP dependencies on every boot so new packages are picked up automatically.
# --no-dev keeps dev tools (phpunit) out of the running container; use `make test`
# which runs via a separate container invocation with dev deps installed.
echo "Syncing PHP dependencies via Composer ..."
composer install --no-dev --no-interaction --no-progress

exec "$@"
