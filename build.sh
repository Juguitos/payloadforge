#!/usr/bin/env bash
# Package the extension into a loadable zip (rename to .xpi, or sign with web-ext).
set -e
cd "$(dirname "$0")"
OUT=web-ext-artifacts
mkdir -p "$OUT"
rm -f "$OUT/payloadforge.zip"
zip -r -FS "$OUT/payloadforge.zip" \
  manifest.json popup background lib icons \
  -x '*.DS_Store' >/dev/null
echo "Built $OUT/payloadforge.zip"
