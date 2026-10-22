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
#   ./test/run.sh ui v5vpn     # 跑 v5vpn UI（见下方"已知问题"）
#   ./test/run.sh all          # go + 两个 UI 场景
#
# 已知问题（v5vpn UI 场景）：
#   搬入的 v5vpn mock 来自分支 hygkui/7，那边客户端用 encode=1（base64）；
#   本分支客户端按 v2.0 标准用 encode=2（AES-128-CBC）。mock 不解 AES，
#   于是把密文当明文比对并返回 0x8000001a（界面上显示为"用户名或密码错误"）。
#   这不是脚本缺陷，而是两个分支的协议实现分叉。在 encode 取值经真实网关
#   仲裁前，保持 mock 原样。
#
# 界面路径：两套前端按协议分开，脚本按场景打开 /atrust/ 或 /v5vpn/；
# 根路径重定向由 internal/cmd 的 Go 测试覆盖。

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

case "$WHAT" in
  go)   run_go ;;
  ui)   run_ui "$SCENARIO" ;;
  all)  run_go; run_ui atrust; run_ui v5vpn ;;
  all-light) run_go; run_ui atrust ;;
  *)
    echo "用法: $0 [go|ui|all|all-light] [atrust|v5vpn]" >&2
    exit 2
    ;;
esac
