package main

// authconfig.go — 构造 /passport/v1/public/authConfig 的响应。
//
// 字段集合与取值直接来自 2026-10-21 对真实网关的一次登录尝试（见
// ATRUST_PROTOCOL_ANALYSIS.md §20.2）。这里刻意保留真实响应的"怪癖"：
//   - pubKeyExp 是十进制字符串 "65537"，不是 hex
//   - enableClientAutoStart 是字符串 "0"，不是布尔
//   - certDomains 为空数组表示不启用证书登录
//   - antiMITMAttackData.enable = 0 时客户端完全跳过反中间人分支
//
// 这些怪癖是 mock 的核心价值：客户端能跑通，就证明我们对这些类型的
// 理解与官方实现一致。

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newHex 生成 n 字节的随机小写 hex（长度 2n）。
func newHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 不可用: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ─────────────────────── 反中间人固定材料（§26）───────────────────────

// fixedChallenge 是下发给客户端的固定挑战，base64(128 字节)，共 172 字符。
//
// 为什么固定：checkChanllege 校验的是「客户端算出 local」与「网关下发 server」
// 是否相等。把 challenge 钉死，客户端算出的 local 也就钉死了，
// 于是可以从客户端日志里读一次、写进 challengeAnswer、永久复用。
//
// 真实网关每次下发新值（日志里 40+ 处长度均为 172/352），但 mock 没有这个约束。
const fixedChallenge = "OeP/y5EhziYE0fnDA222eDzwV21/8j6wCd2fvrc+BIwYVsCqZ1DjI5tgmLmuZZYaXgc+HN2sq5P0FwIa5wJV4LwWytnd5endA4GjIyiXQxtpphL/P6eT7JgHAHAUzfYYIKHwd5+JRI8dQ8gXHYRJE4JZAg+Zpm7AelNc3Rhu0Ds="

// fixedDevicePubKeyMod 是配套的 RSA 模数（512 hex = 256 字节），固定以排除变量。
// 真实网关注册的是它自己的一对钥匙；mock 只需要让它**稳定**，
// 因为 challengeAnswer 是对「这一对固定输入」算出来的。
const fixedDevicePubKeyMod = "ED859AFE9354FF7B9FFAECCCCA3999ED10A39237BE972E343BDD6D2E4657894F67629485D11E83C241238645CE845F317247065907DB789DB9A5B3FE4428639370A3C7C935BA741092D144EBBE1861E430756CAC53EFF476C1D9A259F99F1BF095977D5CC1247F1C407C349D8F28FEA12F60BEA0088BFFA65E6F7F81CEBE95A1AAEF938296F817E654AA095898A7931F9F6F2CAE72D339FBE350B7E3275EE43BC409E88D40A2DB27D170B340BBF66A482796481DCC6A0476809BFCE7706743E3CF74C45CF5A8960771024C07F89DF0127C4E0357DF256E76BEC9C40B854B3700DED66AE563E06C6DD86A36A1C7641ED25C8C1D1A81C9D457DFB9B2A08F1A27EF"

// challengeAnswer 是下发的 encryptedChallenge。
//
// 空串 = 「探针模式」：客户端必然校验失败，但会把算出的期望值打进日志——
//
//	[error][sangfor::checkChanllege:145] challenge verfiy failed; Reason:
//	  pubkey:… challenge: inconsistent encryptedChallenge
//	  local:<32 hex 期望值> server:
//
// 把这个 32 hex 填进来（或用 -challenge-answer 参数 / 环境变量覆盖），
// 校验就会通过，随后 getEntityFromMIMTData 才会执行、signKey 才会落盘。
//
// ⚠ 只有在 challenge 与 devicePubKeyMod 都保持不变时，这个值才有效。
var challengeAnswer = ""

// newUUID 生成 RFC4122 v4 形态的 UUID（真实网关的 csrfToken/unitid 就是这格式）。
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 不可用: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// antiMITMData 对应 authConfig.data.antiMITMAttackData。
// 10 个字段全部保留，即使 enable=0——真实网关也会下发它们。
type antiMITMData struct {
	Enable             int    `json:"enable"`
	DevicePubKeyMod    string `json:"devicePubKeyMod"`
	DevicePubKeyExp    string `json:"devicePubKeyExp"`
	RSACert            string `json:"rsaCert"`
	SM2EncCert         string `json:"sm2encCert"`
	Challenge          string `json:"challenge"`
	EncryptedChallenge string `json:"encryptedChallenge"`
	Ticket             string `json:"ticket"`
	AntiMITMRequest    bool   `json:"antiMITMRequest"`
	MitmSig            string `json:"mitmSig"`
}

type authServerInfo struct {
	LoginDomain string `json:"loginDomain"`
	AuthID      string `json:"authId"`
	AuthType    string `json:"authType"`
	SubType     string `json:"subType"`
	AuthName    string `json:"authName"`
	Description string `json:"description"`
	IconPath    string `json:"iconPath"`
	IconType    string `json:"iconType"`
	LoginURL    string `json:"loginUrl"`
	LogoutURL   string `json:"logoutUrl"`
}

type ecUpgradeConfig struct {
	Enable            int    `json:"enable"`
	CDNEnable         int    `json:"cdnEnable"`
	ATrustDownloadURL string `json:"aTrustDownloadUrl"`
	UnInstEasyConnect int    `json:"unInstEasyConnect"`
	VPNAddress        string `json:"vpnAddress"`
	AlreadyUpdateTip  string `json:"alreadyUpdateTip"`
	ProductName       string `json:"productName"`
}

type authConfigData struct {
	FirstAuth             []string          `json:"firstAuth"`
	DefaultDomain         string            `json:"defaultDomain"`
	Domains               []string          `json:"domains"`
	AuthServerInfoList    []authServerInfo  `json:"authServerInfoList"`
	PubKey                string            `json:"pubKey"`
	PubKeyExp             string            `json:"pubKeyExp"`
	AntiReplayRand        string            `json:"antiReplayRand"`
	ClientVerifyCode      string            `json:"clientVerifyCode"`
	ClientInstallMode     string            `json:"clientInstallMode"`
	EnableClientAutoStart string            `json:"enableClientAutoStart"`
	GUID                  string            `json:"guid"`
	UnitID                string            `json:"unitid"`
	PassportTokenEnable   int               `json:"passportTokenEnable"`
	ThirdAuthQrcodeTime   int               `json:"thirdAuthQrcodeTimeout"`
	Security              map[string]string `json:"security"`
	PortalProtocolKey     string            `json:"portalProtocolKey"`
	AntiMITMAttackData    antiMITMData      `json:"antiMITMAttackData"`
	CertData              map[string]any    `json:"certData"`
	USBKeyData            map[string]any    `json:"usbKeyData"`
	WebDiagnosisConf      map[string]any    `json:"webDiagnosisConf"`
	AutoRedirect          bool              `json:"autoRedirect"`
	AppCenterConfig       map[string]any    `json:"appCenterConfig"`
	RememberPwdConfig     map[string]any    `json:"rememberPwdConfig"`
	SkipAppCenterEnable   string            `json:"skipAppCenterEnable"`
	EnableClientForceUpd  string            `json:"enableClientForceUpdate"`
	EnableStartClient     int               `json:"enableStartClient"`
	IsLogin               int               `json:"isLogin"`
	QyWechatQrcodeConf    map[string]any    `json:"qyWechatQrcodeConf"`
	QyWechatAuthScenario  map[string]any    `json:"qyWechatAuthScenario"`
	DingTalkQrcodeConf    map[string]any    `json:"dingTalkQrcodeConf"`
	DingTalkAuthScenario  map[string]any    `json:"dingTalkAuthScenario"`
	TLSConfig             int               `json:"tlsConfig"`
	ECUpgradeConfig       ecUpgradeConfig   `json:"ECUpgradeConfig"`
	CertDomains           []string          `json:"certDomains"`
	CertPort              string            `json:"certPort"`
	GraphCodePath         string            `json:"graphCodePath"`
}

// buildAuthConfig 每次调用都生成新的 antiReplayRand 与 csrfToken。
// 字段集合对齐 2026-10-21 对真实网关 GET authConfig 的实测（35 键）。
func (s *Server) buildAuthConfig(host string) authConfigData {
	rand16 := newHex(8) // 8 字节 = 16 hex，与真实网关一致
	csrf := newUUID()

	s.mu.Lock()
	s.antiReplayRand = rand16
	s.csrfToken = csrf
	s.mu.Unlock()

	data := authConfigData{
		FirstAuth:     []string{"auth/psw"},
		DefaultDomain: "local",
		Domains:       []string{"local"},
		AuthServerInfoList: []authServerInfo{{
			LoginDomain: "local",
			AuthID:      "1",
			AuthType:    "auth/psw",
			SubType:     "default",
			AuthName:    "本地密码认证",
			Description: "",
			IconPath:    "https://" + host + "/portal/icon/auth_server/auth_psw_default.svg",
			IconType:    "font",
			LoginURL:    "",
			LogoutURL:   "",
		}},
		PubKey:                pubKeyHex(s.rsaKey),
		PubKeyExp:             "65537", // 十进制字符串，不是 hex
		AntiReplayRand:        rand16,
		ClientVerifyCode:      newUUID(),
		ClientInstallMode:     "force",
		EnableClientAutoStart: "0", // 字符串
		GUID:                  s.guid,
		UnitID:                s.unitID,
		PassportTokenEnable:   0,
		ThirdAuthQrcodeTime:   60,
		Security:              map[string]string{"csrfToken": csrf},
		PortalProtocolKey:     newHex(32),
		AntiMITMAttackData: antiMITMData{
			Enable:          s.mitmEnable,
			DevicePubKeyMod: fixedDevicePubKeyMod,
			DevicePubKeyExp: "10001",
			RSACert:         "",
			SM2EncCert:      "",
			// ★ 2026-10-21 15:20 重大更正（§26）：
			//
			// challenge **不能为空**。空串会让客户端的 checkChanllege 直接失败：
			//   [error][sangfor::checkChanllege:145] challenge verfiy failed;
			//     challenge: inconsistent encryptedChallenge local:ABD4… server:
			//   ↑ local 是客户端算出的期望值，server 是空串，必然不等。
			//
			// 失败之后 getEntityFromMIMTData **一次都不会被调用**，signKey 也就
			// 永远不落盘；等 clientResource 要验签时再查库 → 查不到 → 登出。
			// 也就是说 §24.16 看到的「验签失败」其实是**没走到验签**。
			//
			// 反证：10:21 连真实网关那轮，antiMITMRequest 网络请求 0 次，
			// 但 getEntityFromMIMTData 2 次、SdpcPk save 2 次——signKey 是
			// **本地派生**的，不靠任何握手接口。
			//
			// ★ 2026-10-21 晚：两道校验的算法已知（§29），两个值都直接算出来。
			//   encryptedChallenge = AES-CBC-128-PKCS7(challenge) under SHA256(mod+exp+SALT2)
			//   mitmSig            = HMAC-SHA256(signKey, 排序后的 "k:v&…")
			// 计算在 antiMITMPayload 里完成，这里只留占位。
			Challenge:       fixedChallenge,
			Ticket:          s.unitID,
			AntiMITMRequest: false,
		},
		CertData:             map[string]any{"enable": 1, "certList": []any{}},
		USBKeyData:           map[string]any{"enable": 0, "usbKeyList": []any{}},
		WebDiagnosisConf:     map[string]any{"enable": false},
		AutoRedirect:         true,
		AppCenterConfig:      map[string]any{"viewModel": "icon"},
		RememberPwdConfig:    map[string]any{},
		SkipAppCenterEnable:  "1",
		EnableClientForceUpd: "0",
		EnableStartClient:    1,
		IsLogin:              0,
		QyWechatQrcodeConf:   map[string]any{},
		QyWechatAuthScenario: map[string]any{},
		DingTalkQrcodeConf:   map[string]any{},
		DingTalkAuthScenario: map[string]any{},
		TLSConfig:            14,
		ECUpgradeConfig: ecUpgradeConfig{
			Enable:            1,
			CDNEnable:         1,
			ATrustDownloadURL: "https://atrustcdn.sangfor.com/standalone/aTrustInstaller.exe",
			UnInstEasyConnect: 1,
			VPNAddress:        "",
			AlreadyUpdateTip:  "",
			ProductName:       "sdp",
		},
		CertDomains:   []string{}, // 空 ⇒ 不启用证书登录
		CertPort:      "6660",
		GraphCodePath: "/passport/v1/public/graphCheckCodePath",
	}

	// 两道反中间人校验（§29）：把 encryptedChallenge 与 mitmSig 都算成
	// 客户端本地会算出/认可的值。算法已知，无需再从客户端日志回读。
	//
	// -challenge-answer 的覆盖在计算**之前**生效：encryptedChallenge 本身
	// 也是 mitmSig 的签名内容之一，先覆盖后签名才能保证两者自洽。
	if challengeAnswer != "" {
		data.AntiMITMAttackData.EncryptedChallenge = challengeAnswer
	}
	if err := fillAntiMITM(&data.AntiMITMAttackData); err != nil {
		// 算不出来就是配置有问题，宁可显式失败也不下发一个必然被拒的值。
		s.logf("⚠ antiMITM 应答材料计算失败: %v", err)
	}

	// 只返回 authConfig 本体。外层的 {type, data, first} 视图描述
	// 由 authConfigEnvelope 统一包裹，避免重复嵌套。
	return data
}

// authConfigEnvelope 是真实网关的响应外壳。
//
// ★ 2026-10-21 二次实测修正（原文档 §20.2 的三层结构是错的）：
//
//	{code, message, data:{...35 个字段直接平铺...}, traceId}
//
// data 里没有 type / data / first 这三个键——实测报文里 "first_auth"
// 与独立键 "first" 出现次数都是 0。客户端 useInitHelp 直接断言
// data.firstAuth 是数组、data.domains 是数组，若要它穿过 this.data 再取
// 一层就会拿到 undefined，于是日志里出现
//
//	[assert] init auth config data firstAuth not a array
//	[assert] init auth config data domains not a array
//	[UI:init] Init login error {}
//
// 保留 traceId：真实网关每条响应都带，客户端在 parseResponseResult
// 里会读它打日志。
func (s *Server) authConfigEnvelope(host string) map[string]any {
	return map[string]any{
		"code":    0,
		"message": "成功",
		"data":    s.buildAuthConfig(host),
		"traceId": newHex(8),
	}
}
