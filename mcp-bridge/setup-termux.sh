#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

pkg update -y
pkg install -y nodejs-lts

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  printf 'Node.js/npm installation failed.\n' >&2
  exit 1
fi

npm install --omit=dev

if [ -f .env ]; then
  printf 'Existing .env found. It will not be overwritten.\n'
  printf 'Edit mcp-bridge/.env manually to rotate credentials.\n'
else
  printf 'Create your Replicate API token at https://replicate.com/account/api-tokens\n'
  read -r -s -p 'Paste Replicate API token (input hidden): ' REPLICATE_API_TOKEN
  printf '\n'
  if [ -z "$REPLICATE_API_TOKEN" ]; then
    printf 'A Replicate token is required for this bridge.\n' >&2
    exit 1
  fi
  BRIDGE_TOKEN="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')"
  umask 077
  {
    printf 'REPLICATE_API_TOKEN=%s\n' "$REPLICATE_API_TOKEN"
    printf 'MCP_BRIDGE_TOKEN=%s\n' "$BRIDGE_TOKEN"
    printf 'MCP_BRIDGE_PORT=8765\n'
  } > .env
  unset REPLICATE_API_TOKEN
  chmod 600 .env
  printf '\nLocal bridge token (copy it into the Android MCP panel):\n%s\n' "$BRIDGE_TOKEN"
  printf 'The token is saved in mcp-bridge/.env with owner-only permissions.\n'
fi

printf '\nSetup complete. Start the bridge with:\n'
printf '  cd "%s" && set -a && source .env && set +a && npm start\n' "$ROOT"
