#!/bin/sh
set -eu

backend_base_url="${BACKEND_BASE_URL:-}"

if [ -z "$backend_base_url" ]; then
    echo "BACKEND_BASE_URL is required for the frontend API proxy." >&2
    exit 1
fi

if ! printf '%s\n' "$backend_base_url" | grep -Eq '^https?://([A-Za-z0-9-]+\.)*[A-Za-z0-9-]+(:[0-9]{1,5})?/?$'; then
    echo "BACKEND_BASE_URL must be an http(s) origin without path, query, fragment or credentials." >&2
    exit 1
fi

BACKEND_BASE_URL="${backend_base_url%/}"
export BACKEND_BASE_URL

envsubst '${BACKEND_BASE_URL}' < /etc/nginx/default.conf.template > /etc/nginx/conf.d/default.conf
nginx -t
exec nginx -g 'daemon off;'
