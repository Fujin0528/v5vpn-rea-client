#!/usr/bin/env bash
# V5VPN E2E UI Automated Test Runner
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=== [1/3] Checking test certificate ==="
if [ ! -f "results/test-client.p12" ]; then
  echo "Generating test PKCS#12 client certificate..."
  go run gencert.go -out results/test-client.p12 -cn "Leadsec-Admin-Cert" -pwd "123456"
else
  echo "Test certificate exists: results/test-client.p12"
fi

echo "=== [2/3] Checking dependencies ==="
if [ ! -d "node_modules" ]; then
  npm install
fi

echo "=== [3/3] Running E2E UI automation test with Microsoft Edge ==="
node e2e_ui_test.js

echo ""
echo "================================================================="
echo "✅ Test run complete!"
echo "   - HTML Test Report : $DIR/results/report.html"
echo "   - Test Log         : $DIR/results/test.log"
echo "   - Screenshots      : $DIR/results/screenshots/"
echo "================================================================="
