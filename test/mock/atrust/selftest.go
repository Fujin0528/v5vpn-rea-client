//go:build ignore

// selftest — 模拟官方 aTrust 客户端的调用序列，验证 mock 网关行为正确。
//
// 它严格按 ATRUST_PROTOCOL_ANALYSIS.md §20.1 的真实时序走一遍：
//
//	authConfig → manifest → authConfig → psw → onlineInfo → clientResource
//
// 并用与官方客户端相同的算法加密口令（PKCS#1 v1.5 + 245 字符分块 + 小写 hex），
// 这样 mock 侧的解密成功就等价于"官方客户端提交的密文能被我们解开"。
//
// 注意：这个自测验证的是 **mock 自身的一致性**，不能替代"官方客户端连上来"。
// 后者才是真正的对撞验证。
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"

	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

// acResp 对应真实响应 {code, message, data:{...平铺的 authConfig 本体...}, traceId}。
//
// ★ 这里曾经写成两层 data（data.data），那是错的：2026-10-21 对真实网关
// 的两次实测都表明 data 是平铺的（35 个键，没有 type/data/first）。
// 官方客户端也是直接读 data.firstAuth / data.domains。
type acResp struct {
	Code int `json:"code"`
	Data struct {
		PubKey         string `json:"pubKey"`
		PubKeyExp      string `json:"pubKeyExp"`
		AntiReplayRand string `json:"antiReplayRand"`
		Security       struct {
			CSRFToken string `json:"csrfToken"`
		} `json:"security"`
		GUID string `json:"guid"`
	} `json:"data"`
}

var base string
var cli *http.Client

func main() {
	// 默认跑 8443：443 可能被本机其它服务占用（mock 的 -addr 默认值仍是 443，
	// 与真实网关一致，但日常验证用 8443 更省事，不必抢特权端口）。
	base = "https://127.0.0.1:8443"
	if len(os.Args) > 1 {
		base = os.Args[1]
	}
	cli = &http.Client{
		Timeout: 10 * time.Second,
		// cookie jar 必须要有：真实网关靠 cookie 维持渲染层会话，
		// mock 在 psw 里 Set-Cookie（§24.10）。没有 jar 就验证不到这条路径。
		Jar: mustCookieJar(),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	fail := 0
	check := func(name string, ok bool, detail string) {
		if ok {
			fmt.Printf("  ✅ %s\n", name)
		} else {
			fmt.Printf("  ❌ %s  %s\n", name, detail)
			fail++
		}
	}

	fmt.Println("=== 0. 登录前探测（无任何凭据）===")
	// ★ 必须在任何登录动作之前跑：此时 cookie jar 为空、也没有 Sid-Ticket。
	// 历史版本里 lookupSession 会"兜底"返回任意残留会话，于是登录前探测
	// 拿到 isOnline:true，客户端 Me() 因此跳过 an()+Ee()，原生 agent 永远
	// 不被拉起，界面卡在「登录中」（§24.6）。
	oiAnon := doJSON("GET", "/passport/v1/user/onlineInfo", nil, nil)
	oiAnonData, _ := oiAnon["data"].(map[string]any)
	check("onlineInfo(登录前) isOnline=false", oiAnonData["isOnline"] == false, fmt.Sprint(oiAnonData["isOnline"]))
	check("onlineInfo(登录前) code=0（不是错误码）", num(oiAnon["code"]) == 0, fmt.Sprint(oiAnon["code"]))

	fmt.Println("=== 1. GET /public/manifest ===")
	man := doJSON("GET", "/public/manifest?lang=zh-CN&platform=Windows&clientType=SDPClient", nil, nil)
	manData, _ := man["data"].(map[string]any)
	server, _ := manData["server"].(string)
	check("manifest 返回 server 含 'aTrust'", strings.Contains(server, "aTrust"), "server="+server)
	_, hasCaps := manData["capacities"].(map[string]any)
	check("manifest 含 capacities", hasCaps, "")

	fmt.Println("=== 2. GET /passport/v1/public/authConfig ===")
	// ★ 必须用 GET：实测只有 GET 返回 35 键平铺的 authConfig 本体，
	// POST 是 ticket 交换通道，data 恒为 {}（§22.1）。
	ac := doJSON("GET", "/passport/v1/public/authConfig?clientType=SDPClient&platform=Windows&lang=zh-CN&needTicket=1", nil, nil)
	var cfg acResp
	remarshal(ac, &cfg)
	check("authConfig code=0", num(ac["code"]) == 0, fmt.Sprint(ac["code"]))
	check("pubKey 长度=512", len(cfg.Data.PubKey) == 512, fmt.Sprint(len(cfg.Data.PubKey)))
	check("pubKeyExp=\"65537\"（十进制字符串）", cfg.Data.PubKeyExp == "65537", cfg.Data.PubKeyExp)
	check("antiReplayRand 长度=16", len(cfg.Data.AntiReplayRand) == 16, cfg.Data.AntiReplayRand)
	check("csrfToken 非空", cfg.Data.Security.CSRFToken != "", "")
	check("guid 长度=64", len(cfg.Data.GUID) == 64, cfg.Data.GUID)

	fmt.Println("=== 3. 用 authConfig.pubKey 加密口令（复刻官方算法）===")
	pub := parseRSA(cfg.Data.PubKey, cfg.Data.PubKeyExp)
	plain := "mock-password" + "_" + cfg.Data.AntiReplayRand
	cipherHex := encryptChunked(pub, plain)
	check("密文块数 = 1（短口令）", len(cipherHex) == 512, fmt.Sprint(len(cipherHex)))

	fmt.Println("=== 4. POST /passport/v1/auth/psw ===")
	hdr := map[string]string{
		"x-csrf-token":  cfg.Data.Security.CSRFToken,
		"x-sdp-traceid": randHex(4),
		"Content-Type":  "application/json;charset=utf-8",
	}
	pswBody := map[string]any{
		"username":       "mockuser@local",
		"password":       cipherHex,
		"rememberPwd":    "0",
		"graphCheckCode": "",
	}
	psw := doJSON("POST", "/passport/v1/auth/psw?clientType=SDPClient&platform=Windows&lang=zh-CN", pswBody, hdr)
	pswData, _ := psw["data"].(map[string]any)
	sid, _ := pswData["sidTicket"].(string)
	check("psw code=0", num(psw["code"]) == 0, fmt.Sprint(psw["code"]))
	check("psw 返回 sidTicket", len(sid) == 64, sid)

	fmt.Println("=== 5. GET /passport/v1/auth/authCheck ===")
	// ★ 这一步存在的理由：psw 的 nextService 必须是 "auth/authCheck"
	// （客户端分发表只有 auth/authCheck 与 auth/accessCheck 两个键），
	// 且 authCheck 必须回空 nextService —— 客户端只有在这种情况下
	// 才会执行 detectClient() + startClient() 拉起原生 agent。
	// nextService 拼错会让整条登录链静默结束，界面永远停在"登录中"（§24.3）。
	pswNext, _ := pswData["nextService"].(string)
	check("psw.nextService 是可识别的键", pswNext == "auth/authCheck" || pswNext == "auth/accessCheck", pswNext)
	ac2 := doJSON("GET", "/passport/v1/auth/authCheck", nil, map[string]string{"sid-ticket": sid})
	ac2Data, _ := ac2["data"].(map[string]any)
	check("authCheck code=0", num(ac2["code"]) == 0, fmt.Sprint(ac2["code"]))
	check("authCheck.nextService 为空（触发客户端拉起 agent）", ac2Data["nextService"] == "", fmt.Sprint(ac2Data["nextService"]))
	for _, col := range []string{"actionType", "action", "policyId", "reason", "sidTicket"} {
		_, has := ac2Data[col]
		check("authCheck 含 ACL 列 "+col, has, "缺列会让客户端打 acl data column error")
	}

	// ★ cookie 往返：渲染层的请求体 token 恒为空、也不带 Sid-Ticket 头，
	// 只靠浏览器自动携带的 cookie。所以必须验证 psw 下发的 cookie 能认回会话。
	acCookie := doJSON("GET", "/passport/v1/auth/authCheck", nil, nil) // 不带任何手写 header
	acCookieData, _ := acCookie["data"].(map[string]any)
	check("authCheck(仅靠 cookie) code=0", num(acCookie["code"]) == 0, fmt.Sprint(acCookie["code"]))
	check("authCheck(仅靠 cookie) 能认出会话", acCookieData["sidTicket"] == sid, fmt.Sprintf("got=%v want=%v", acCookieData["sidTicket"], sid))

	fmt.Println("=== 6. GET /passport/v1/user/onlineInfo ===")
	// ★ 关键回归：**登录前**（无任何凭据）必须返回 isOnline:false。
	//
	// 历史版本里 lookupSession 会"兜底"返回任意残留会话，于是登录前探测
	// 拿到 isOnline:true，客户端 Me() 因此跳过 an()+Ee()，原生 agent 永远
	// 不被拉起，界面卡在「登录中」（§24.6）。
	//
	// ⚠ 这条断言必须在**登录后**的步骤之前跑，否则 cookie jar 已含有会话，
	// 测到的就不是"登录前"了。这里的检查放在 step 0 完成（见下）。
	oi := doJSON("GET", "/passport/v1/user/onlineInfo", nil, map[string]string{"Sid-Ticket": sid})
	oiData, _ := oi["data"].(map[string]any)
	check("onlineInfo(带 token) isOnline=true", oiData["isOnline"] == true, fmt.Sprint(oiData["isOnline"]))

	fmt.Println("=== 7. POST /controller/v1/user/clientResource ===")
	cr := doJSON("POST", "/controller/v1/user/clientResource", map[string]any{}, map[string]string{
		"sid-ticket":   sid,
		"x-csrf-token": cfg.Data.Security.CSRFToken,
	})
	check("clientResource code=0", num(cr["code"]) == 0, fmt.Sprint(cr["code"]))

	fmt.Println("=== 7b. POST /passport/v1/public/sessionIdExchange（表单编码）===")
	// ★ 这个接口的真实请求是 application/x-www-form-urlencoded + 表单体
	// `sidTicket=<64 hex>`，UA 为 `SPCClientType aTrustTray`（原生 agent 发出）。
	// 它曾经是"未实现的路径"，导致登录链在这里断掉（§24.12）。
	// 这里就用表单编码复现，验证 mock 不会只吃 JSON。
	//
	// ★★ 更关键的是**它必须回 Set-Cookie**：紧随其后 agent 会并发发
	//      GET /passport/v1/user/onlineInfo
	//      POST /passport/v1/security/passportTokenExchange
	//    这两个请求都不带 Sid-Ticket 头，只靠 cookie jar。少下发一次 cookie
	//    就会让 onlineInfo 返回 isOnline:false，agent 判定 login failed，
	//    界面永远停在「登录中」——而 mock 侧所有接口都返回 code:0（§24.14）。
	sie := doForm("/passport/v1/public/sessionIdExchange?lang=zh-CN&platform=Windows&clientType=SDPClient",
		url.Values{"sidTicket": {sid}})
	check("sessionIdExchange code=0（表单体）", num(sie["code"]) == 0, fmt.Sprint(sie["code"]))
	sieData, _ := sie["data"].(map[string]any)
	check("sessionIdExchange 认出会话", sieData["sessionId"] == sid, fmt.Sprint(sieData["sessionId"]))
	// 用一个**全新的、没有 cookie 的**客户端复现 agent 的后续请求：
	// sessionIdExchange 之后那条连接上必须已有可用的 sidTicket cookie。
	fresh := &http.Client{
		Timeout: 10 * time.Second,
		Jar:     mustCookieJar(), // 必须有 jar，否则收不到 Set-Cookie，这条断言就空转
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	probe := doFormWith(fresh, "/passport/v1/public/sessionIdExchange?lang=zh-CN&platform=Windows&clientType=SDPClient",
		url.Values{"sidTicket": {sid}})
	check("sessionIdExchange（无 cookie 客户端）成功", num(probe["code"]) == 0, fmt.Sprint(probe["code"]))
	var cookieSeen string
	if u, err := url.Parse(base); err == nil {
		if cs := fresh.Jar; cs != nil {
			for _, c := range cs.Cookies(u) {
				if c.Name == "sidTicket" {
					cookieSeen = c.Value
				}
			}
		}
	}
	check("sessionIdExchange 下发 sidTicket cookie（agent 后续 onlineInfo 依赖它）",
		cookieSeen == sid, fmt.Sprintf("got=%q want=%q", cookieSeen, sid))

	fmt.Println("=== 7c. POST /passport/v1/public/ticketExchange（表单编码）===")
	// 与 sessionIdExchange 不同：这个的响应体**会被读取**——
	// 客户端 ve() 取 data.sidTicket 再交给 /v1/service/start。
	te := doForm("/passport/v1/public/ticketExchange?lang=zh-CN&platform=Windows&clientType=SDPClient",
		url.Values{"sidTicket": {sid}})
	check("ticketExchange code=0", num(te["code"]) == 0, fmt.Sprint(te["code"]))
	teData, _ := te["data"].(map[string]any)
	ticket, _ := teData["sidTicket"].(string)
	check("ticketExchange 返回 sidTicket（客户端会读它）", len(ticket) == 64, fmt.Sprint(len(ticket)))

	fmt.Println("=== 8. 反中间人端点（enable=0 时不应主动调用）===")
	am := doJSON("POST", "/controller/v1/public/antiMITMRequest", map[string]any{}, nil)
	check("antiMITMRequest 可响应（手动调用）", num(am["code"]) == 0, fmt.Sprint(am["code"]))

	fmt.Println()
	if fail == 0 {
		fmt.Println("全部通过 —— mock 自身行为与规范一致。")
		fmt.Println("⚠ 但这只是自洽验证；真正的协议对撞需要官方客户端连上来。")
	} else {
		fmt.Printf("有 %d 项失败\n", fail)
		os.Exit(1)
	}
}

// ---------- 复刻官方客户端的加密算法 ----------

// parseRSA 对应官方 `r.setPublic(pubKey, parseInt(pubKeyExp,10).toString(16))`。
func parseRSA(modHex, expDec string) *rsa.PublicKey {
	n := new(big.Int)
	n.SetString(modHex, 16)
	e, _ := new(big.Int).SetString(expDec, 10)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}
}

// encryptChunked 对应官方 encrypt()：每 245 字符一块，PKCS#1 v1.5，小写 hex 无分隔符。
func encryptChunked(pub *rsa.PublicKey, s string) string {
	const chunk = 245
	var out strings.Builder
	for i := 0; i < len(s); i += chunk {
		end := i + chunk
		if end > len(s) {
			end = len(s)
		}
		ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(s[i:end]))
		if err != nil {
			panic(err)
		}
		out.WriteString(hex.EncodeToString(ct))
	}
	return out.String()
}

// doForm 用 application/x-www-form-urlencoded 发请求，复刻原生 agent 的调用形态
// （sessionIdExchange / ticketExchange 都是这种编码，不是 JSON）。
func doForm(path string, vals url.Values) map[string]any {
	return doFormWith(cli, path, vals)
}

// doFormWith 允许指定 client，用于构造"没有 cookie jar"的对照场景。
func doFormWith(c *http.Client, path string, vals url.Values) map[string]any {
	req, err := http.NewRequest("POST", base+path, strings.NewReader(vals.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "SPCClientType aTrustTray")
	resp, err := c.Do(req)
	if err != nil {
		fmt.Printf("  ⚠ 请求失败 POST %s: %v\n", path, err)
		return map[string]any{}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		fmt.Printf("  ⚠ 非 JSON 响应 POST %s (%d): %s\n", path, resp.StatusCode, truncate(string(raw), 200))
		return map[string]any{}
	}
	return m
}

// mustCookieJar 建一个标准 cookie jar，用于模拟浏览器自动携带 cookie。
func mustCookieJar() http.CookieJar {
	j, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return j
}

// ---------- 极简 HTTP 辅助 ----------

func doJSON(method, path string, body any, hdr map[string]string) map[string]any {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		panic(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := cli.Do(req)
	if err != nil {
		fmt.Printf("  ⚠ 请求失败 %s %s: %v\n", method, path, err)
		return map[string]any{}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		fmt.Printf("  ⚠ 非 JSON 响应 %s %s (%d): %s\n", method, path, resp.StatusCode, truncate(string(raw), 200))
		return map[string]any{}
	}
	return m
}

func remarshal(from map[string]any, to any) {
	b, _ := json.Marshal(from)
	_ = json.Unmarshal(b, to)
}

func num(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return -1
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
