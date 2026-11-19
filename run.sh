#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PORT="${NGINX2ROOT_PORT:-8095}"
echo "Starting nginx2root scanner on 0.0.0.0:${PORT} ..."
exec python3 server.py
