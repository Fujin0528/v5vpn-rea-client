package main

// endpoints.go — 其余网关接口。
//
// 报价原则：**不确定的字段宁可少给，也不要编造**。编造会让客户端
// 走入一个真实网关不会出现的行为，从而污染验证结论。
// 因此这里的响应只包含：
//   1. ATRUST_PROTOCOL_ANALYSIS.md 中有实证/源码依据的字段；
//   2. 客户端明确会读取的字段（见 web/assets 的用法）。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// manifestJS 对应 /public/manifest.js。
//
// ★ 这是整个 mock 里最容易写错的一个接口：它**不是 JSON**。
// 真实网关返回的是 102 字节的 application/javascript：
//
//	var entranceConfig = {"entrance":{"type":"portal","i18nVersionType":"cn"},"aioClient":{"enable":true}}
//
// 客户端的 index.html 用 <script src="/public/manifest.js?v=…"> 直接引入它，
// 由浏览器执行成全局变量 window.entranceConfig。前端在
// utils_method.*.js 的模块顶层就读：
//
//	window.entranceConfig.entrance.type   → platformType
//	window.entranceConfig.entrance.i18nVersionType
//
// 读不到就打 `window.entranceConfig.entrance undefined, api manifest.js data error`
// 并退回 Portal 默认分支。
//
// 注意 entrance.type 必须是 "portal"：它决定 isPortal=true，进而决定
// enableQrcode / enableMiddleAttack / needClient 等一堆分支。
func (s *Server) handleManifestJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.WriteHeader(http.StatusOK)
	body, _ := json.Marshal(map[string]any{
		"entrance": map[string]any{
			"type":            "portal",
			"i18nVersionType": "cn",
		},
		"aioClient": map[string]any{"enable": true},
	})
	_, _ = w.Write([]byte("var entranceConfig = " + string(body) + ";\n"))
}

// handlePortalInfo 对应 /static/.portal.json —— 本地化（portal 静态资源）的版本描述。
//
// 客户端 WebDirManager.checkStorage 用它的 md5 判断"网关是否下发了新的
// portal 前端包"。md5 与本地默认值一致时走 `had storaged portal files`
// 分支，直接复用安装目录里的 web/，不下载 portal.zip。
//
// mock 刻意返回与安装目录**相同的 md5**（见 localPortalMD5 常量注释），
// 这样客户端永远复用本地前端，我们不需要实现 portal.zip / 签名校验。
func (s *Server) handlePortalInfo(w http.ResponseWriter, r *http.Request) {
	s.replyJSON(w, map[string]any{
		"version":     "2.5.16.21",
		"isCustom":    false,
		"forceUpdate": false,
		"capacities":  map[string]any{"acl_localization": true},
		"md5":         localPortalMD5,
	})
}

// localPortalMD5 是 aTrustTray/resources/app/static/.portal.json 里记录的
// 本地前端包 md5。返回同值 ⇒ 客户端认定"本地已有一份完整的 portal"。
//
// 这是 mock 的一个受控偏离：真实网关下发的 md5 取决于其 portal 版本。
// 偏离的后果仅限"不下载前端包"，不影响任何登录协议字段。
const localPortalMD5 = "131f92e5ce2859390584d85e0fa9630c"

// handleThemeManifest 对应 /portal/theme/manifest.json —— 登录页外观配置。
//
// 客户端 WebDirManager.checkThemeUpdated 的判定是
//
//	themeUpdated = (localRand != serverRand || css 不可用) && serverRand
//
// 首次连 mock 时本地 themes/127.0.0.1@443/ 不存在 ⇒ css 不可用 ⇒ 弹一次
// "主题更新"提示并下载 theme_skin.css。下载完成后本地 rand 与 serverRand
// 一致，后续不再提示。这里给出与真实网关同构的全字段，rand 用真实网关的
// "00000000" 取值风格——注意 getServerThemeRand 有 `|| "1"` 兜底，
// 所以返回空串并不会抑制弹窗，不如老实给一个真值。
func (s *Server) handleThemeManifest(w http.ResponseWriter, r *http.Request) {
	s.replyJSON(w, map[string]any{
		"background":          "login_bg.png",
		"logo":                "logo.png",
		"clientLoginBg":       "client_login_bg.png",
		"clientLoginBgEn":     "client_login_bg.png",
		"organizeName":        "",
		"organizeNameEN":      "",
		"noticeTitle":         "温馨提示",
		"noticeTitleEN":       "Tips",
		"serviceTips":         "",
		"serviceTipsEN":       "",
		"loginTips":           "aTrust Mock Gateway",
		"loginTipsEN":         "aTrust Mock Gateway",
		"loginAgreement":      true,
		"downloadClient":      true,
		"externalLinks":       []any{},
		"externalLinkTitle":   "更多",
		"externalLinksEN":     []any{},
		"externalLinkTitleEN": "",
		"appBackground":       "service_bg.png",
		"logoIcon":            "logo_icon.png",
		"appCenterTitle":      "工作台",
		"appCenterTitleEN":    "",
		"appApply":            true,
		"appNoAvailableTip":   "未配置应用",
		"appNoAvailableTipEN": "",
		"appAllHideTip":       "应用已隐藏",
		"appAllHideTipEN":     "",
		"title":               "aTrust",
		"titleEN":             "aTrust",
		"clientName":          "aTrust",
		"clientNameEN":        "aTrust",
		"rand":                "00000000",
		"filingInformation":   "",
		"filingInformationEN": "",
	})
}

// themeCSS 是一份最小但结构正确的主题变量表。
// 客户端会读它并做 checkThemeCssOutDate 检查（看是否缺关键变量），
// 所以不能返回空内容或 JSON。
const themeCSS = `:root {
  --theme-color-primary: #1c6eff;
  --theme-color-primary-l50: #e8f4ff;
  --theme-color-primary-l30: #96c7ff;
  --theme-color-primary-l10: #3e85f7;
  --theme-color-primary-d10: #0d51d9;
  --theme-color-error: #e34d59;
  --theme-color-warning: #ff9d00;
  --theme-color-success: #2ba471;
  --theme-text-primary: #1f2733;
  --theme-text-secondary: #5c6b7f;
  --theme-bg-primary: #ffffff;
}
`

func (s *Server) handleThemeCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(themeCSS))
}

// handleCopywriting 对应 /resource/client/getCopywriting。
// 客户端只从中取 workbenchLabel / greetWordsInfo 等文案，缺字段不会阻断登录，
// 但缺失会在托盘端打 `clientConfig not find` 并退回本地文案。
func (s *Server) handleCopywriting(w http.ResponseWriter, r *http.Request) {
	s.replyJSON(w, map[string]any{
		"code":     0,
		"message":  "OK",
		"traceId":  newHex(8),
		"sourceId": "",
		"data": map[string]any{
			"labelInfo": map[string]any{"workbenchLabel": "工作台"},
			"greetWordsInfo": map[string]any{
				"title":      "欢迎使用",
				"subTitle":   "请点击开始办公后，访问业务系统",
				"buttonText": "开始办公",
			},
			"workbenchCopywritingInfo": map[string]any{"tips": "欢迎使用工作台"},
			"enUs": map[string]any{
				"labelInfo": map[string]any{"workbenchLabel": "Work"},
				"greetWordsInfo": map[string]any{
					"title":      "Welcome",
					"subTitle":   "Please click Start Working to access the business system",
					"buttonText": "Start Working",
				},
				"workbenchCopywritingInfo": map[string]any{"tips": "Welcome to the workbench"},
			},
		},
	})
}

// handleManifest 对应 §3.1。客户端据此判定「这是不是 aTrust 网关」，
// 判定条件是 data.server 含子串 "aTrust"。
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r)
	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "OK",
		"data": map[string]any{
			"server":          "aTrust/2.5.16",
			"i18nVersionType": "cn",
			"trustDevice":     map[string]any{"enable": true},
			"guid":            s.guid,
			"capacities":      s.capacities(),
			"options": map[string]any{
				"aioClient": map[string]any{"enable": true},
				"tun0rtt":   map[string]any{"enable": true},
			},
			"addr": "https://" + host,
		},
	})
}

// capacities 对齐真实网关下发的 41 项（§20.5）。少给几项不会阻断登录，
// 但会影响客户端分支走向，所以尽量给全。
func (s *Server) capacities() map[string]any {
	v := func(ver string) map[string]any { return map[string]any{"version": ver} }
	return map[string]any{
		"certInfo":       v("1.0.0.0"),
		"xtunnelOptions": v("1.0.0.0"),
		"weakPwd":        v("1.0.0.0"),
		"cdn":            v("1.0.0.0"),
		"clientResource": map[string]any{
			"version":               "1.0.0.0",
			"appList":               v("1.0.0.0"),
			"spaSeed":               v("1.0.0.0"),
			"openModel":             v("1.0.0.0"),
			"antiUninstall":         v("1.0.0.0"),
			"tunv6":                 v("1.0.0.0"),
			"clientAdvanceDebugger": v("1.0.0.0"),
		},
		"trustedApplication": v("1.0.0.1"),
		"adaptiveAuth":       v("1.0.0.1"),
		"antiMITMAttack":     v("1.0.0.3"),
		"verifyInterfaceSig": v("1.0.0.1"),
		"uemAppStore":        v("1.0.0.2"),
		"standaloneClient":   v("1.0.0.2"),
		"quickSocks5":        v("1.0.0.1"),
		"forgetPassword":     v("1.0.0.0"),
		"appLock":            v("1.0.0.1"),
		"multiSandbox":       v("1.0.0.1"),
		"aioClient":          v("1.0.0.0"),
		"uemAppSso":          v("1.0.0.0"),
		"linuxWorkSpace":     v("1.0.0.0"),
		"simplifyWorkspace":  v("1.0.0.0"),
		"uemVirtualNet":      v("1.0.0.0"),
		"uemAudit":           v("1.0.0.0"),
		"uemShare":           v("1.0.0.1"),
		"recommendApp":       v("1.0.0.0"),
		"onlinePolicy":       v("1.0.0.0"),
		"localClientVersion": v("1.0.0.0"),
		"quickLogout":        v("1.0.0.0"),
		"tun0rtt":            v("1.0.0.0"),
		"linuxClipboard":     v("1.0.0.0"),
		"reportEnv":          v("1.0.0.0"),
		"blockTcpDns":        v("1.0.0.0"),
		"spaSupportIPv6":     v("1.0.0.0"),
		"NFSDesktop":         v("1.0.0.0"),
	}
}

// handleAuthConfig 对应 §4 / §22.1。
//
// ★ 两条通道的语义不同，实测（2026-10-21）如下：
//
//	GET  → data 是**平铺的 35 键** authConfig 本体（这才是取配置的主路径）
//	POST → 只做 ticket 交换，data = {}（body 为空对象时才是 75500004）
//
// POST 的真实 body 是 **94 字节的三键能力协商占位**：
//
//	{"spa":{},"xtunnelOptions":{},"certInfo":{}}
//
// 早期版本把它写成 {"needTicket":1}，那是错的——needTicket 在 query 里，
// body 里只有上面三个键。两者的共同点是"body 非空"，所以只看
// "空 body 会报 75500004" 是能对上的，但据此反推 body 结构就会错。
//
// 早期版本还让 GET 也走三层包封，两个错叠在一起，导致客户端
// `firstAuth not a array` 断言失败、登录页初始化直接 error。
//
// 这里对 POST 仍比真实网关"宽容"一点：哪怕 body 是空对象也返回成功体，
// 避免 mock 卡在客户端某条重试分支上（真实网关返回 75500004）。
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.replyJSON(w, s.authConfigEnvelope(hostOf(r)))
		return
	}
	// POST：只回 ticket 交换的结果，data 为空——与真实网关一致。
	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data":    map[string]any{},
		"traceId": newHex(8),
	})
}

// handleOnlineInfo 对应 §7.3。渲染层最关心 data.isOnline。
//
// ★ 无会话时**不能**返回错误码 10000004。
//
// 这个接口在**登录前**就会被调用（客户端启动、路由守卫、setUserStatus 都会调
// `an()` → 这里）。而 `an()` 的语义只是"查一下我是不是已经在线"，
// 未登录是**正常答案**，不是错误。返回 10000004 会让客户端把它当成
// SESSION_INVALID 处理，往"会话失效"分支跑。
//
// 更要命的是历史版本里 lookupSession 会对无 token 的请求"兜底"返回任意
// 残留会话，于是登录前这个接口返回 isOnline:true，直接让客户端
// `Me()` 跳过 `an() + Ee()`（启动原生 agent 的唯一入口）——
// 界面永远停在「登录中」。详见 §24.8。
func (s *Server) handleOnlineInfo(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.lookupSession(r)
	if !ok {
		// 未登录：正常的"不在线"，不是错误
		s.replyJSON(w, map[string]any{
			"code":    0,
			"message": "成功",
			"data":    map[string]any{"isOnline": false},
		})
		return
	}
	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data": map[string]any{
			"isOnline":    true,
			"userName":    sess.Username,
			"displayName": sess.Username,
			"domain":      "local",
			"sidTicket":   sess.Sid,
			"status":      "online",
			"loginTime":   sess.Created.Format("2006-01-02 15:04:05"),
		},
	})
}

// handleClientResource 对应 §8.1。
//
// ★ 2026-10-21 晚：结构改为真机的三层嵌套（§4.2 / libreatrust resource.rs）：
//
//	data.appList.data.appInfo[]      ← 资源分组
//	              .apps[]            ← 具体应用
//	              .addressList[]     ← 实际路由条目 {protocol, port, host}
//
// 早期版本返回的是扁平的 data.appList.data.domainList / ipList——那是猜的，
// 客户端并不认，于是资源列表空白且没有任何报错。
//
// 资源按「能访问」「能验证路由」两类设计：
//   - 域名资源指向 localhost 上的 mock 自身，用户点开能看到响应，
//     证明链路（而不是只能看到一条不可验证的记录）
//   - 内网地址资源用于验证 addressList 的 IP/CIDR 解析
func (s *Server) handleClientResource(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.lookupSession(r)
	if !ok {
		// 资源树确实需要会话，这里返回 10000004 是合理的（与 onlineInfo 不同）
		s.replyJSON(w, map[string]any{"code": 10000004, "message": "session invalid", "data": map[string]any{}})
		return
	}
	s.logf("  clientResource 请求（用户 %s）——下发 %d 个应用分组", sess.Username, len(mockAppInfo()))

	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data": map[string]any{
			"appList": map[string]any{
				"code": 0,
				"data": map[string]any{
					"appInfo": mockAppInfo(),
					// ★ config.nodeGroupConf 是**必填**的。
					//
					// libreatrust 的 AppListData 里 `config: AppConfig` 没有
					// `#[serde(default)]`，也就是说整棵资源树会因为缺它而解析
					// 失败——客户端拿到 code:0、也提示"刷新成功"，但列表是空的。
					// 这正好是"刷新成功但界面没东西"的成因。
					//
					// nodeGroupConf 承载的是数据面接入线路（441/TCP-TLS），
					// 客户端要拿它才知道往哪里建隧道。mock 不提供数据面，
					// 所以这里填自己的地址——形状对即可。
					"config": map[string]any{
						"nodeGroupConf": mockNodeGroupConf(),
					},
				},
			},
			// favoriteAppList / featureCenter 客户端也会读，给空结构而不是缺键，
			// 避免它把 undefined 当成解析失败。
			"favoriteAppList": map[string]any{"code": 0, "data": []any{}},
			"featureCenter":   map[string]any{"code": 0, "data": []any{}},
			"sdpPolicy": map[string]any{
				"code": 0,
				"data": map[string]any{
					"clientOption": map[string]any{
						"dnsOption": map[string]any{
							"enable":          false,
							"enableTunnelDNS": false,
							"firstDNS":        "",
							"secondDNS":       "",
						},
					},
				},
			},
			"uemPolicy":       map[string]any{"code": 0, "data": map[string]any{}},
			"spaSeed":         map[string]any{"seedID": ""},
			"appProcessRules": map[string]any{"code": 0, "data": []any{}},
		},
	})
}

// mockNodeGroupConf 构造数据面接入线路配置。
//
// 字段语义来自 libreatrust resource.rs 的消费逻辑：
//
//	majorNodeGroup.id      ← 默认使用的节点组
//	nodeGroupList[].id     ← 资源条目的 nodeGroupId 对应到这里
//	addressInfo[].type     ← "wan" 表示可用线路（其他类型被忽略）
//	addressInfo[].address  ← "host:port"，缺端口时补 :441
//
// 还有一条特殊约定：address 恰好等于 "{{sdpcHost}}" 时，客户端会把它
// 替换成网关自身地址。mock 直接用这个占位符，这样不论用户从哪个 IP
// 访问（127.0.0.1 或局域网地址）都能拿到正确的主机名。
func mockNodeGroupConf() map[string]any {
	return map[string]any{
		"majorNodeGroup": map[string]any{
			"id": "mock-node-group",
		},
		"nodeGroupList": []any{
			map[string]any{
				"id": "mock-node-group",
				"addressInfo": []any{
					// 441 是数据面隧道的固定端口。mock 不提供数据面，
					// 但形状必须对——客户端要据此建立隧道，缺了就会在
					// 资源加载阶段直接失败。
					map[string]any{"type": "wan", "address": "{{sdpcHost}}"},
				},
			},
		},
	}
}

// mockApp 构造一条资源，补上渲染层要求的三个字段。
//
// ★ associated / ext 不是可选的（§29.12）。渲染层 apps.js 的过滤条件是：
//
//	if ("ALLWEB" !== e.subModel && e.associated && !e.ext.hide) { 保留 }
//	else if (this._isVdiApp(e) && …) { 单独收走 }
//
// 缺 associated ⇒ undefined 是假值 ⇒ **每一条资源都被丢掉**，界面上就只剩
// 「未配置应用」。而 ext 同样不能省：一旦 associated 为真，`e.ext.hide`
// 会在 ext 缺失时抛 TypeError（`&&` 短路保护不到它），整个 _buildAppHash 挂掉。
//
// app 级别的 accessModel 另有用途：_buildAppHash 用它置两个全局开关
// （Ze = 存在 L3VPN 资源，tr = 存在 WEB 资源且 domainList 非空），
// hasTunnelApp() / hasDnsWebApp() 读这两个开关决定界面走哪条渲染路径。
// 只写在 group 上不够——读的是 app。
func mockApp(id, name string, addressList []any) map[string]any {
	return map[string]any{
		"id":          id,
		"name":        name,
		"nodeGroupId": "mock-node-group",
		"accessModel": "L3VPN", // ir
		"subModel":    "L3VPN", // 只要不是 "ALLWEB"
		"associated":  true,
		"ext":         map[string]any{"hide": false},
		"addressList": addressList,
	}
}

// mockAppInfo 构造资源分组。
//
// 每条 addressList 条目的字段名必须用 {protocol, port, host}——
// 这是两份独立开源实现（geektrust §4.2 与 libreatrust resource.rs）
// 一致确认的形状。ip 是可选字段，用于「域名 + 内网 IP」双路由。
//
// 分组的键是 **grpid**，不是 id：渲染层写的是
//
//	const {grpid: o, apps: a} = n
//
// 少了 grpid，分组会以 undefined 为键塞进哈希表，后续按 grpid 查分组全是空的。
// id 仍然保留，用于展示与调试。
func mockAppInfo() []any {
	return []any{
		map[string]any{
			"id":            "mock-group-1",
			"grpid":         "mock-group-1",
			"name":          "演示资源",
			"accessModel":   "L3VPN",
			"subModel":      "L3VPN",
			"accessAddress": "",
			"nodeGroupId":   "mock-node-group",
			"apps": []any{
				// 指向 mock 自己的 HTTPS 端口：点开能真的看到响应，
				// 可以用来验证「资源可达」而不只是「列表有行」。
				mockApp("mock-app-1", "Mock 控制台 (本机 8443)", []any{
					map[string]any{"protocol": "tcp", "port": "8443", "host": "127.0.0.1"},
				}),
				mockApp("mock-app-2", "Mock 控制台 (本机 443)", []any{
					map[string]any{"protocol": "tcp", "port": "443", "host": "127.0.0.1"},
				}),
				// 域名 + 内网 IP 双路由：验证 addressList 里同一个 host
				// 既有域名解析又有固定 IP 的写法。
				mockApp("mock-app-3", "内网 Web (域名+IP)", []any{
					map[string]any{
						"protocol": "tcp",
						"port":     "443",
						"host":     "mock-resource.internal",
						"ip":       []any{"10.15.45.163"},
					},
					map[string]any{"protocol": "tcp", "port": "443", "host": "10.15.45.163"},
				}),
			},
		},
		map[string]any{
			"id":          "mock-group-2",
			"grpid":       "mock-group-2",
			"name":        "内网网段",
			"accessModel": "L3VPN",
			"subModel":    "L3VPN",
			"nodeGroupId": "mock-node-group",
			"apps": []any{
				mockApp("mock-app-4", "办公网段 10.20.0.0/16", []any{
					map[string]any{"protocol": "tcp", "port": "0", "host": "10.20.0.0/16"},
				}),
				mockApp("mock-app-5", "数据库 3306", []any{
					map[string]any{"protocol": "tcp", "port": "3306", "host": "10.20.1.5"},
				}),
			},
		},
	}
}

// handleAntiMITM 只在 mitm=1 时才会被调用。一旦命中，
// 说明我们成功让官方客户端走进了反中间人分支——
// 这正是拿到 X-Request-Sig 真实样本的途径（§21.6 第 7 步）。
func (s *Server) handleAntiMITM(w http.ResponseWriter, r *http.Request) {
	s.logf("")
	s.logf("★★★ 收到 /controller/v1/public/antiMITMRequest ★★★")
	s.logf("    这是首次拿到反中间人挑战的真实报文，请立即保存请求日志！")
	s.logf("    重点看 X-Request-Sig / X-Response-Sig 头与 body 结构")
	s.logf("")
	s.replyJSON(w, map[string]any{
		"code":     0,
		"message":  "成功",
		"data":     map[string]any{"isAttack": false},
		"isAttack": false,
	})
}

// handleGraphCode 图形验证码：mock 永不要求验证码，
// 但客户端可能在首页探测该路径，返回一张 1x1 PNG 以免报错。
func (s *Server) handleGraphCode(w http.ResponseWriter, r *http.Request) {
	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data":    map[string]any{"graphCheckCodeEnable": 0},
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.logf("  收到登出请求")
	s.replyJSON(w, map[string]any{"code": 0, "message": "成功", "data": map[string]any{}})
}

// handleSpaConfig 对应 SPA（单包敲门）配置。
//
// 客户端在拿到资源树后会请求它，用来决定是否要先发 SPA 包才能建隧道。
// 本机真实网关 `spaEnable:false`，mock 也关掉——否则客户端会尝试发送
// SPA 包，而 mock 并不解析它，只会让链路更难排查。
//
// proxyAddresses 仍然要给：即使不开 SPA，客户端也会从这里读数据面线路，
// 与 clientResource 的 nodeGroupConf 是两条并行的来源。
func (s *Server) handleSpaConfig(w http.ResponseWriter, r *http.Request) {
	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data": map[string]any{
			"spaEnable":      false,
			"udpSpaEnable":   false,
			"proxyAddresses": []any{"{{sdpcHost}}:441"},
			"seedID":         "",
		},
	})
}

// handleIcon 返回一个极简 SVG，满足 authServerInfoList[].iconPath。
const mockSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">` +
	`<rect width="32" height="32" rx="6" fill="#2b6cb0"/>` +
	`<text x="16" y="22" font-size="16" fill="#fff" text-anchor="middle" font-family="sans-serif">M</text></svg>`

func (s *Server) handleIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mockSVG))
}

// handleSessionIdExchange 对应 POST /passport/v1/public/sessionIdExchange。
//
// 语义（源码级）：old/jssdk/api.js 的 `e.sidExchange`：
//
//	SFRequest.createRequest({type:"server", method:"post",
//	                         path:"/passport/v1/public/sessionIdExchange", data:e})
//
// 调用方 `ne({sidTicket})`（web/assets/common.844141aa.js 的 restoreSession）
// **完全不读取响应体**——它只关心这次调用是否成功。失败时 restoreSession 会抛
// RESTORE_SESSION_ERROR，整条恢复链中断。
//
// ★ 请求形态的细节（实测 2026-10-21 13:44:53）：
//
//	User-Agent: SPCClientType aTrustTray          ← 原生 agent，不是浏览器
//	Content-Type: application/x-www-form-urlencoded   ← 表单，不是 JSON
//	body: sidTicket=<64 hex>                       ← 74 字节
//
// 这与其它 passport 接口的 JSON 风格不同，实现时容易只按 JSON 解析而失败。
// 因此这里两种格式都接受：先按表单解析，再回退 JSON，最后回退 cookie。
func (s *Server) handleSessionIdExchange(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	raw := strings.TrimSpace(string(body))

	tok := ""
	if vals, err := url.ParseQuery(raw); err == nil {
		tok = vals.Get("sidTicket")
	}
	if tok == "" && strings.HasPrefix(raw, "{") {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			if v, ok := m["sidTicket"].(string); ok {
				tok = v
			}
		}
	}
	if tok == "" {
		if c, err := r.Cookie(cookieSidTicket); err == nil {
			tok = c.Value
		}
	}

	s.mu.Lock()
	sess, ok := s.sessions[tok]
	s.mu.Unlock()

	if !ok {
		s.logf("⚠ sessionIdExchange 票据无效（body=%q）—— 仍返回成功，避免打断恢复链", truncForLog(raw))
		s.replyJSON(w, map[string]any{"code": 0, "message": "成功", "data": map[string]any{}})
		return
	}

	s.logf("  sessionIdExchange：用户 %s 的会话已确认", sess.Username)

	// ★ 必须在这里**再下发一次 cookie**。
	//
	// 原生 agent 在 sessionIdExchange 之后会立刻并发发两个请求：
	//
	//	GET  /passport/v1/user/onlineInfo
	//	POST /passport/v1/security/passportTokenExchange
	//
	// 这两个请求**都不带 Sid-Ticket 头、也不带任何显式凭据**（实测见
	// requests.log 14:21:03.391：只有 UA 和 X-Sdp-Traceid）。它们靠的是
	// 同一条 keep-alive 连接上此前 Set-Cookie 积累下来的 cookie jar。
	//
	// 如果这里不发 cookie，onlineInfo 就没有会话 → 返回 isOnline:false →
	// agent 侧判定：
	//
	//	[LoginBusinessHanderImpl::handleOnlinInfoAndPassportTokenResult:244]
	//	After exchange session, the user is not online;
	//	HowTo: this is an unexpected situation,please check with sdpc
	//	[LoginBusinessHanderImpl::handleLoginErrorImpl:325] login failed
	//
	// 界面表现就是永远停在「登录中」——注意这一步**在 mock 侧看起来一切正常**
	// （所有接口都返回 code:0），失败只发生在 agent 的内部判定里。
	setSidCookie(w, sess.Sid)

	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data": map[string]any{
			"sessionId": sess.Sid,
			"sidTicket": sess.Sid,
		},
	})
}

// handleTicketExchange 对应 POST /passport/v1/public/ticketExchange。
//
// 客户端 `ve()`（web/assets/common.844141aa.js）用它把当前会话换成一次性
// ticket，然后交给原生 agent 的 `POST /v1/service/start`：
//
//	const {data: n} = yield ee();   // ee = ticketExchange
//	log.info("Get sid ticket success"), e = n.sidTicket, F(e), e
//
// 与 sessionIdExchange 不同，**这个响应体是被读取的**：必须回 `data.sidTicket`，
// 否则 `e` 为 undefined，后续 `/v1/service/start` 会带着空票据。
//
// 请求形态与 sessionIdExchange 同构（原生 agent 发出、表单编码），
// 但为稳妥两种编码都接受。
func (s *Server) handleTicketExchange(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	raw := strings.TrimSpace(string(body))

	tok := ""
	if vals, err := url.ParseQuery(raw); err == nil {
		tok = vals.Get("sidTicket")
	}
	if tok == "" && strings.HasPrefix(raw, "{") {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			if v, ok := m["sidTicket"].(string); ok {
				tok = v
			}
		}
	}
	// 会话凭据也可能在 cookie / header 里（浏览器路径）
	s.mu.Lock()
	sess, ok := s.sessions[tok]
	if !ok {
		cand := r.Header.Get("sid-ticket")
		if cand == "" {
			if c, err := r.Cookie(cookieSidTicket); err == nil {
				cand = c.Value
			}
		}
		if cand != "" {
			sess, ok = s.sessions[cand]
		}
	}
	s.mu.Unlock()

	if !ok {
		s.logf("⚠ ticketExchange 找不到会话（body=%q）—— 生成临时票据以免打断链路", truncForLog(raw))
		// 仍然给一张可用票据：后续 /v1/service/start 会拿它去换会话语义。
		// 这是 mock 的受控偏离，真实网关会返回业务错误。
		tmp := s.createSession("anonymous")
		s.replyJSON(w, map[string]any{
			"code":    0,
			"message": "成功",
			"data":    map[string]any{"sidTicket": tmp, "ticket": newHex(16)},
		})
		return
	}

	s.logf("  ticketExchange：为用户 %s 换发一次性 ticket", sess.Username)
	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data": map[string]any{
			"sidTicket": sess.Sid,
			"ticket":    newHex(16),
		},
	})
}

// setSidCookie 下发会话 cookie。psw 与 sessionIdExchange **都必须调用它**。
//
// 渲染层和原生 agent 发请求时都不显式带票据：前者请求体里的 token 恒为空串
// （old/jssdk/common.js 的 createRequest），后者的 onlineInfo /
// passportTokenExchange 也只有 UA 和 X-Sdp-Traceid。两边都依赖 cookie jar。
//
// 少下发一次，就会出现「所有接口都返回 code:0，但 agent 内部判定登录失败」
// 这种在 mock 侧完全看不出来的故障。
func setSidCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieSidTicket,
		Value:    sid,
		Path:     "/",
		HttpOnly: false, // 前端需要读它做后续判断，不能 HttpOnly
		SameSite: http.SameSiteNoneMode,
		Secure:   true, // 全站 HTTPS
	})
}

// truncForLog 截断过长的日志内容（票据是 64 hex，不必全量打印）。
func truncForLog(v string) string {
	if len(v) <= 96 {
		return v
	}
	return v[:96] + "…"
}

// hostOf 取客户端实际访问的 host:port，用于回填 iconPath 与 addr 这类
// 带绝对 URL 的字段——硬编码会让客户端去连一个不存在的地址。
func hostOf(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	if r.TLS != nil {
		return strings.TrimSuffix(r.URL.Host, ":")
	}
	return "127.0.0.1"
}
