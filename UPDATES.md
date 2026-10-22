# 更新弹窗说明（update-*.json 的 notes 来源）

这个文件只服务客户端「检查更新」弹窗：`mygo build` 从这里提取 `## <版本号>`
段落写入 `update-<os>-<arch>.json` 的 `notes` 字段。GitHub Release 页面的完整
发布说明仍然来自 `CHANGELOG.md`，两者不要混写。

写法约束（弹窗是原生对话框，不渲染 Markdown）：

- 每个版本 **10 行以内**，一段导语 + 若干条一句话要点；
- 不用 `###` 小标题、表格、代码块、链接；
- 详细内容留给 `CHANGELOG.md`，结尾可提示「详细说明见 GitHub Release 页面」。

## 0.4.0

支持深信服 aTrust 零信任网关，与 V5VPN 双协议并存。

- 新增 aTrust 零信任登录、流式隧道与内网资源访问
- 新增「口令 + 证书」双因子登录（界面新标签页与 -pwd-cert 命令行）
- V5VPN 与 aTrust 界面按协议独立，启动自动进入上次使用的协议
- 口令登录编码对齐原厂（Base64 + encode=1）
- 证书登录仅支持本地 .p12/.pfx 文件，移除 Windows 系统证书库
- 测试与 mock 网关收进仓库，新增协议集成测试与 UI 端到端测试

详细说明见 GitHub Release 页面。
