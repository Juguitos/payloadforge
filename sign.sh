#!/usr/bin/env bash
# Sign the extension via Mozilla AMO (self-distribution / unlisted channel).
# Requires AMO_JWT_ISSUER and AMO_JWT_SECRET in the environment.
# Output: a signed .xpi in web-ext-artifacts/
set -e
cd "$(dirname "$0")"

if [ -z "$AMO_JWT_ISSUER" ] || [ -z "$AMO_JWT_SECRET" ]; then
  echo "ERROR: set AMO_JWT_ISSUER and AMO_JWT_SECRET first."
  echo "  Get them at https://addons.mozilla.org/developers/addon/api/key/"
  echo '  export AMO_JWT_ISSUER="user:12345:67"'
  echo '  export AMO_JWT_SECRET="your-secret"'
  exit 1
fi

npx --yes web-ext@8.2.0 sign \
  --channel=unlisted \
  --api-key="$AMO_JWT_ISSUER" \
  --api-secret="$AMO_JWT_SECRET" \
  --source-dir=. \
  --artifacts-dir=web-ext-artifacts

echo
echo "Done. Signed .xpi is in web-ext-artifacts/"
echo "Install it: Firefox -> about:addons -> gear -> Install Add-on From File..."
