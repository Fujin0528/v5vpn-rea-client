# v5vpn-rea

基于 **REA (Reverse Engineer Anything)** 逆向分析技术与 **MyGo** 跨平台桌面技术架构，重新实现的现代化 V5VPN 客户端。

---

## 1. 目标与技术参考

- **逆向分析参考**：[morluto/rea](https://github.com/morluto/rea)
- **待逆向目标软件**：`C:\Program Files (x86)\V5VPN` (网御星云 / LeadSec 系列 VPN)
- **重新实现技术架构**：[egoist/mygo](https://github.com/egoist/mygo) (纯 Go 桌面开发框架，系统原生 WebView2 + 强类型 IPC)

---

## 2. 逆向工程成果 (REA Key Findings)

通过对 `SecUI.exe`、`SecController.dll`、`SecLogin.dll`、`SecSSL.dll`、`VpnServ.exe` 进行符号表、反汇编及内存映射分析，完全破解了以下关键机制：

### 2.1 本地凭证解密 (setting.xml)
- **用户名**：标准 Base64 编码。
- **密码**：DES-CBC，PKCS5/PKCS7 填充
- 解密还原率 100%，支持自动导入或反向导出。

### 2.2 协议交互流程 (Network Protocol)
1. **版本探针**：`GET /vpn/version.xml` $\rightarrow$ `<VERSION major="2" minor="0"/>`。
2. **加密口令认证**：`POST /vpn/user/auth/password`
   - 加密算法：AES-128-CBC，PKCS7 填充，Raw 字符串拼接（避免 URL 转义 Base64 尾部字符）
   - **关键参数 `encode`**：
     - `encode=2`：**2.0 网关标准**，指示网关使用 AES-128-CBC 解密。若误填 `encode=1`，网关会按 v1.0 纯 Base64 解码，导致解密密文为乱码并报 `0x8000001A (用户名或密码错误)`。
     - `encode=1`：v1.0 旧版网关模式，仅对明文口令做 Base64 编码。
   - 字段：`username={EncUser}&password={EncPwd}&encode=2&verifycode={code}`。
   - 登录成功返回 Session Cookie：`VSG_SESSIONID`。
3. **获取授权资源**：`GET /vpn/user/portal/intergration.xml?version=2.0`
   - 获得 TCP/UDP 内网资源列表与端口、策略及 DNS。
4. **隧道建立与数据透传**：
   - 本地自动分配代理端口监听。
   - 建立 SSL 连接并发送 `CONNECT {TargetIP}:{TargetPort} HTTP/1.1\r\nCookie: VSG_SESSIONID={SessionID}` 进行全双工透传。
5. **保活心跳**：`GET /vpn/user/portal/intergration.xml?period={interval}&version=2.0`。
6. **安全登出**：`GET /vpn/user/logout`。

---

## 3. 兼容性

| 项目 | 版本 / 范围 |
|:---|:---|
| 已在其中完成端到端验证的原厂客户端 | 5.3.3.x 系列 |
| 网关协议版本 | v2.0 (`/vpn/version.xml` 返回 `major=2 minor=0`) |
| 支持的登录方式 | 口令登录 (`/vpn/user/auth/password`) |
| 未支持 | 证书登录、匿名登录、国密(SM2/SM3/SM4)套件、IPsec/NDIS 虚拟网卡模式 |

本项目仅实现「SSL VPN 门户 + HTTP CONNECT 隧道透传」这条路径，
不实现原客户端的内核态虚拟网卡（SecTap.sys / ndislwf.sys）与 IPsec 功能，
因此**不能替代**原厂客户端用于全网状路由场景。
其他 5.x 版本未经验证，可能因协议字段变化而不可用。

端到端连通性已在两套生产网关上验证完成（具体网关地址、账号、密码等
细节不在仓库内公开，请勿在 issue、PR、截图或日志中粘贴）。

---

## 4. 快速运行与使用

### 4.1 编译客户端
```bash
go build -o v5vpn-rea.exe ./internal/cmd
```

### 4.2 图形界面 (GUI) 模式
直接运行可启动 MyGo 现代桌面客户端，系统托盘自启：
```bash
.\v5vpn-rea.exe
```
也可在任意浏览器中访问本地 Web 管理控制台：
```
http://127.0.0.1:45678
```

### 4.3 命令行 (CLI) 快速工具

#### 一键提取并解密系统 V5VPN 本地已存的所有账号密码：
```bash
.\v5vpn-rea.exe -dump-passwords
```

#### 查看已配置网关：
```bash
.\v5vpn-rea.exe -cli
```

#### 命令行直连网关：
```bash
.\v5vpn-rea.exe -cli -connect "<gateway-name>" -user "<username>" -pwd "<password>"
```

---

## 5. 项目目录结构

```
v5vpn-rea/
├── internal/             # 内部 Go 源码（不对外暴露 import 路径）
│   ├── cmd/              # 入口程序 (MyGo 桌面窗口生命周期、系统托盘、CLI分发)
│   │   └── ui/           # 嵌入式响应式前端界面 (HTML5 / CSS3 / ES6)
│   ├── config/           # 配置文件解析与本地凭证导入 (setting.xml)
│   ├── crypto/           # DES-CBC / AES-128-CBC 编解码核心算法实现
│   ├── protocol/         # V5VPN 网关 REST/HTTPS 协议客户端与心跳管理器
│   ├── proxy/            # 本地 TCP 端口映射与 SSL HTTP CONNECT 隧道代理引擎
│   └── service/          # 供 MyGo 前端调用的强类型 IPC 业务服务
├── configs/              # 本地运行配置（含保存凭证，已移出版本控制）
├── assets/               # 原创多分辨率盾牌图标与静态资源
├── docs/                 # 逆向分析参考资料与发布检查清单
├── build.bat             # Windows 一键构建脚本
├── go.mod
└── README.md
```
