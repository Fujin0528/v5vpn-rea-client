#!/usr/bin/env bash
# run.sh — v5vpn-rea 测试总入口。
#
# 两层测试：
#   go    协议级集成测试（快、可进 CI）：测试自己构建并拉起 mock 子进程。
#   ui    浏览器端到端（慢、需本机 Edge）：驱动真实 Web UI 连 mock 网关。
#
# 用法：
#   ./test/run.sh              # 跑 go + aTrust UI
#   ./test/run.sh go           # 只跑 go 集成测试
#   ./test/run.sh ui           # 只跑 aTrust UI
#   ./test/run.sh ui v5vpn     # 跑 v5vpn UI
#   ./test/run.sh v5vpn-multi  # 跑 v5vpn 全场景（10合1）双因素/三因素/单口令/证书/改密/验证码/短信/动态令牌UI回归
#   ./test/run.sh all          # go + aTrust UI + v5vpn UI

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/.." && pwd)"

WHAT="${1:-all-light}"
SCENARIO="${2:-atrust}"

run_go() {
  echo "=== Go 集成测试（含自拉起 mock） ==="
  cd "$REPO_ROOT"
  go test -short ./internal/atrust/... ./internal/service/... ./test/... "$@"
}

run_ui() {
  local scenario="${1:-atrust}"
  echo "=== UI 端到端测试（场景: ${scenario}） ==="
  cd "$DIR"
  if [ ! -d node_modules ]; then
    echo "安装依赖: npm install"
    npm install --no-audit --no-fund
  fi
  node e2e_ui_test.js --scenario="$scenario"
  echo ""
  echo "报告: $DIR/results/report-${scenario}.html"
  echo "日志: $DIR/results/test-${scenario}.log"
}

run_v5vpn_multi() {
  echo "=== V5VPN 全场景 10 合 1 多重登录与异常路径测试 ==="
  cd "$DIR"
  if [ ! -d node_modules ]; then
    echo "安装依赖: npm install"
    npm install --no-audit --no-fund
  fi
  node e2e_v5vpn_multi_test.js
  echo ""
  echo "报告: $DIR/results/report.html"
  echo "日志: $DIR/results/test.log"
}

case "$WHAT" in
  go)          run_go ;;
  ui)          run_ui "$SCENARIO" ;;
  v5vpn-multi) run_v5vpn_multi ;;
  all)         run_go; run_ui atrust; run_ui v5vpn ;;
  all-light)   run_go; run_ui atrust ;;
  *)
    echo "用法: $0 [go|ui|v5vpn-multi|all|all-light] [atrust|v5vpn]" >&2
    exit 2
    ;;
esac
