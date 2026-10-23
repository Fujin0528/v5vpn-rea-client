# test/ — 测试与 mock 网关

这个目录把**测试和它依赖的 mock 网关**一起收进仓库。目的是让协议验证可以被持续
迭代：改客户端时，`go test` 就能发现行为偏离；改协议理解时，UI 端到端能看到界面
实际表现。

## 目录结构

```
cmd/
  mock-v5vpn/   V5VPN 网关模拟服务入口
  mock-atrust/  aTrust 网关模拟服务入口
  e2e-v5vpn/    V5VPN 客户端协议对撞工具
  e2e-atrust/   aTrust 客户端协议对撞工具
test/
  mock/
    atrust/     aTrust 零信任网关 mock 实现
    v5vpn/      V5VPN / 网御网关 mock 实现（package mockserver，可被测试 import）
  e2e_ui_test.js          自拉起生命周期的轻量 UI E2E（支持 atrust 与 v5vpn 场景）
  e2e_v5vpn_multi_test.js V5VPN 11合1多重认证与异常流深度自动化测试（含2FA/三因素链/全链挑战/单口令/证书/改密/图形验证码/短信/动态令牌等）
  run.sh                  总入口：go 集成测试 + UI 端到端
  results/                运行期产物（报告、逐步截图、日志），已 gitignore
```

两套 mock 的形态不同是有原因的，不是收拾不干净：

| | `mock/atrust` | `mock/v5vpn` |
|:---|:---|:---|
| 包形态 | `package main`（可执行） | `package mockserver`（库）+ `cmd/mockserver` 入口 |
| 为何如此 | 它是对撞**官方 aTrust 客户端**的测试基准，必须能单独运行 | 它只服务本项目测试，库形态方便在进程内起停 |
| 能否被测试 import | 不能（`package main`） | 能 |
| 测试怎么用它 | `os/exec` 拉起子进程，随机端口 | 同进程 `New()` + 随机端口 |

## 跑测试

```bash
./test/run.sh                 # go 集成测试 + aTrust UI 端到端
./test/run.sh go              # 只跑 Go（快，CI 用这个）
./test/run.sh ui              # 只跑 aTrust UI
./test/run.sh ui v5vpn        # 跑 v5vpn 基础 UI
./test/run.sh v5vpn-multi     # 跑 V5VPN 11合1 全场景双因素/三因素链/全链挑战/图形验证码/在线改密/短信/动态令牌 E2E
./test/run.sh all             # 全部
```

`v5vpn-multi` 会自动生成并导入两张客户端测试证书，界面上按名字区分：

- `单因素证书登录`：用于证书免密入口（「🪪 使用客户端证书直接登录」）的纯证书认证；
- `双因素证书`：用于口令提交后证书挑战模态（`0x2`）中呈递的证书因子。

证书文件生成在 `test/results/`（已 gitignore），口令均为 `123456`。

UI 端到端**不需要提前启动任何进程**：脚本自己构建 mock 与客户端、分配随机端口、
跑完即清理。它还需要本机装有 Edge 或 Chrome（可用 `EDGE_PATH` 环境变量指定）。

两套前端按协议物理分开（`/atrust/` 与 `/v5vpn/`），UI 脚本按场景直接打开对应界面；
根路径 `/` 的重定向（按 `lastUseGateway` 协议选界面）由 `internal/cmd` 的 Go 测试覆盖。

## 三条约定

### 1. mock 是裁判，不改它去迁就实现

`mock/atrust` 来自独立目录 `atrust-mock`，在那里被**冻结为测试基准**：它的价值
在于"官方客户端能连上"。为了让我们的客户端通过而去改 mock，等于把裁判拉到我们这边。

搬进仓库时它**一个协议字节都没改**，只有路径变了。

### 2. 测试自己拉起 mock，不依赖"先手工起服务"

`internal/atrust/e2e_mock_test.go` 用 `mockproc_test.go` 里的 harness 构建并拉起
`test/mock/atrust`，随机端口，`t.Cleanup` 里杀进程删目录。这样：

- 一条命令可复现，CI 里也能跑；
- 不会和正在跑的其它 mock 抢 8443。

想连一个已在跑的外部 mock（比如对撞真实网关）：

```bash
ATRUST_MOCK_URL=https://127.0.0.1:8443 go test ./internal/atrust/ -run TestE2EAgainstMock -v
```

设了该变量就不自拉起；连不上则 skip（外部依赖不该让 CI 变红）。

### 3. UI 测试必须隔离 APPDATA

客户端把 `setting.xml` 和设备标识放在 `%APPDATA%\v5vpn-rea\`。那里存着**真实账号
口令**。UI 脚本启动客户端时把 `APPDATA` 指向临时目录，测试网关只写进那里。

不隔离的后果是把测试数据混进开发机的真实配置——这是测试工具最不该犯的错。

## 已知问题：v5vpn 的 encode 分叉

`ui v5vpn` 场景目前**失败**，原因不是脚本缺陷：

- 本分支客户端按 v2.0 标准用 `encode=2` 提交 AES-128-CBC 密文；
- `mock/v5vpn` 搬自分支 `hygkui/7`，那边客户端用 `encode=1`（base64），mock 只解 base64；
- 于是 mock 把 AES 密文当明文比对，返回 `0x8000001a`：
  界面表现为「网关提示：用户名或密码错误，请检查输入的账号或密码！」。

日志里能看到 `username="xbsgn8j4V8reUtvmfXMVew=="` —— 那是 AES 密文，不是用户名。

哪一边对，要靠真实网关仲裁（见 `.backup/atrust/ATRUST_PROTOCOL_ANALYSIS.md` 与
项目记忆里的 encode 记录）。在仲裁之前保持 mock 原样，失败就是**有用的信号**。

在双分支合并后，`mock/v5vpn/client_integration_test.go` 已正式纳入日常测试执行，默认验证两步串行双因素认证与内网资源拉取。

## 写新测试时的位置约定

- **协议层**（帧格式、认证链、解析）→ `internal/<pkg>/*_test.go`，连 mock 就走自拉起 harness；
- **UI 层**（表单 → API → 渲染）→ `test/e2e_ui_test.js` 里加场景；
- **mock 自身的行为**→ `test/mock/<proto>/*_test.go`。

不要把协议断言写进 UI 脚本，也不要让 UI 脚本依赖人工启动的服务。
