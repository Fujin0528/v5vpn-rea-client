package main

// main.go — mock aTrust 网关。
//
// 用途：让**官方 aTrust 客户端**连上来，用我们依据
// ATRUST_PROTOCOL_ANALYSIS.md 实现的接口去验证协议理解是否正确。
//
// 为什么这个验证有效：官方客户端是独立实现。它能跑通，说明我们读对了；
// 它跑不通，说明我们的规范有错——两个方向都是有价值的信息。
//
// 安全边界：
//   - 只监听 127.0.0.1，不对外暴露。
//   - 不使用任何真实凭证；客户端随便填什么口令都会"登录成功"。
//   - 不接触真实网关，不消耗任何账号配额。

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

func nowStr() string { return time.Now().Format("2006-01-02 15:04:05.000") }

// cookieSidTicket 是会话 cookie 名。
//
// 真实网关用 cookie 维持渲染层的会话：渲染层的所有请求体里
// `token` 恒为空字符串，`setSidTicket()` 只把票据写进 sessionStorage，
// 真正的会话识别靠浏览器自动携带的 cookie（§24.10）。
const cookieSidTicket = "sidTicket"

// Server 持有 mock 网关的全部可变状态。
type Server struct {
	rsaKey *rsa.PrivateKey

	mu             sync.Mutex
	guid           string
	unitID         string
	csrfToken      string
	antiReplayRand string
	mitmEnable     int
	sessions       map[string]*session

	// dataDir 用于持久化 sessions.json（见 persistSessions）。
	dataDir string

	// events 长轮询相关：见 events.go。
	// eventWake 用于唤醒挂起中的轮询，避免必须等满 timeout。
	eventSeq  int64
	nextEvent *eventEnvelope
	eventWake chan struct{}

	logMu sync.Mutex
	logF  *os.File

	verbose bool
}

type session struct {
	Sid      string
	Username string
	Created  time.Time
}

// rsaKeyT 已删除：直接使用 *rsa.PrivateKey。

func (s *Server) logf(format string, args ...any) {
	line := fmt.Sprintf("[%s] %s", nowStr(), fmt.Sprintf(format, args...))
	s.logMu.Lock()
	defer s.logMu.Unlock()
	fmt.Println(line)
	if s.logF != nil {
		fmt.Fprintln(s.logF, line)
	}
}

// record 把一次请求的完整细节落到日志文件——这是本 mock 的**核心产出**，
// 用于与 ATRUST_PROTOCOL_ANALYSIS.md 逐条比对。
func (s *Server) record(r *http.Request, body []byte) {
	if !s.verbose {
		return
	}
	hdrs := make([]string, 0, len(r.Header))
	for k, v := range r.Header {
		hdrs = append(hdrs, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
	}
	sort.Strings(hdrs)

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n╔══ %s %s %s\n", nowStr(), r.Method, r.URL.RequestURI())
	fmt.Fprintf(&sb, "║ from       %s\n", r.RemoteAddr)
	fmt.Fprintf(&sb, "║ host       %s  tls=%v\n", r.Host, r.TLS != nil)
	for _, h := range hdrs {
		fmt.Fprintf(&sb, "║ %s\n", h)
	}
	if len(body) > 0 {
		fmt.Fprintf(&sb, "║ body (%d B)\n", len(body))
		if len(body) <= 4096 {
			fmt.Fprintf(&sb, "║   %s\n", redactBody(string(body)))
		} else {
			fmt.Fprintf(&sb, "║   %s… （已截断）\n", redactBody(string(body[:4096])))
		}
	}
	sb.WriteString("╚══\n")
	s.logMu.Lock()
	defer s.logMu.Unlock()
	fmt.Print(sb.String())
	if s.logF != nil {
		fmt.Fprint(s.logF, sb.String())
	}
}

// redactBody 把长 hex / 长 base64 折叠成摘要，避免日志刷屏，
// 同时保留长度信息（长度本身常是关键证据）。
func redactBody(b string) string {
	if len(b) < 80 {
		return b
	}
	// 找到 "password":"<hex>" 并把值折叠
	return collapseLongRuns(b)
}

const maxRun = 96

// collapseLongRuns 把「连续 ≥96 个 hex 字符」折叠成 <N hex>，
// 让 requests.log 里的 512/512+ 位密文与公钥不撑爆日志，
// 同时保留长度信息（长度本身常是关键证据）。
//
// 注意：只折叠「连续 hex 字符构成的串」，非 hex 字符原样输出。
// 早期版本曾用「同一个字符重复 N 次」作为判据，并且在没有 run 时
// 把非 hex 字符整段丢弃，导致 94 字节的 JSON body 被打印成
// `a"elcerfo` 这种乱码——证据被毁，已修正。
func collapseLongRuns(s string) string {
	isHex := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		if !isHex(s[i]) {
			out.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && isHex(s[j]) {
			j++
		}
		if n := j - i; n >= maxRun {
			fmt.Fprintf(&out, "<%d hex>", n)
		} else {
			out.WriteString(s[i:j])
		}
		i = j
	}
	return out.String()
}

// responseSigPlaceholder 是实验开关：非空时给每条 JSON 响应都带上
// 这个 X-Response-Sig 值（用于对照实验，会让验签必然失败）。
//
// ⚠ 正常路径**不使用**它：见 replyJSON 里基于 signKey 的真实签名。
var responseSigPlaceholder = ""

// signKeyFn 由启动时注入：返回当前会话的 signKey。
// 为空时表示还没有可用的 antiMITM 材料，这时不发 X-Response-Sig。
var signKeyFn func() []byte

func (s *Server) replyJSON(w http.ResponseWriter, v any) {
	// ★ 必须先序列化成字节再签名。
	//
	// 客户端算的是 HMAC(signKey, **响应体原文**)，因此签名覆盖的必须是
	// 实际写到连接上的那些字节。用 json.Encoder 直接写 w 的话，拿到的
	// 是一份"我不知道长什么样"的字节，签名就无从谈起。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // 与真实网关一致：不转义 < > &
	_ = enc.Encode(v)
	body := buf.Bytes()

	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	switch {
	case responseSigPlaceholder != "":
		// 对照实验：故意给错的值
		w.Header().Set("X-Response-Sig", responseSigPlaceholder)
	case signKeyFn != nil:
		if key := signKeyFn(); len(key) > 0 {
			w.Header().Set("X-Response-Sig", computeResponseSig(key, body))
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) createSession(user string) string {
	sid := newHex(32) // 64 hex
	s.mu.Lock()
	s.sessions[sid] = &session{Sid: sid, Username: user, Created: time.Now()}
	sessions := make([]*session, 0, len(s.sessions))
	for _, v := range s.sessions {
		sessions = append(sessions, v)
	}
	s.mu.Unlock()
	s.persistSessions(sessions)
	return sid
}

// sessionsFile 把会话落到磁盘，让 mock 重启后旧 cookie 仍然有效。
//
// ★ 为什么需要：改一次 mock 就要重启一次，而重启会清空内存里的 sessions。
// 此时客户端还握着上一轮的 sidTicket cookie，于是下一次 clientResource 直接
// 拿到 10000004 session invalid，界面上表现为「刷新失败」。
// 这个假失败会掩盖真正在验证的东西（比如响应签名），排查时会走错方向。
//
// 安全性：只存 sid 与用户名，不含任何真实凭据；mock 只监听 127.0.0.1。
const sessionsFile = "sessions.json"

type sessionRecord struct {
	Sid      string `json:"sid"`
	Username string `json:"username"`
	Created  int64  `json:"created"`
}

func (s *Server) persistSessions(list []*session) {
	recs := make([]sessionRecord, 0, len(list))
	for _, v := range list {
		recs = append(recs, sessionRecord{Sid: v.Sid, Username: v.Username, Created: v.Created.Unix()})
	}
	b, err := json.Marshal(recs)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(s.dataDir, sessionsFile), b, 0o600)
}

// loadSessions 在启动时恢复会话。
func (s *Server) loadSessions() int {
	b, err := os.ReadFile(filepath.Join(s.dataDir, sessionsFile))
	if err != nil {
		return 0
	}
	var recs []sessionRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		s.logf("⚠ 会话文件解析失败，忽略: %v", err)
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range recs {
		// 过期时间放宽到 24h：mock 的会话本来就没有真实的有效期语义，
		// 这里只是防止无限堆积。
		if time.Since(time.Unix(r.Created, 0)) > 24*time.Hour {
			continue
		}
		s.sessions[r.Sid] = &session{Sid: r.Sid, Username: r.Username, Created: time.Unix(r.Created, 0)}
	}
	return len(s.sessions)
}

// lookupSession 按请求携带的会话凭据精确查找会话。
//
// ★ 这里曾经有一段「兜底：只要有一个会话就返回它」的逻辑，它是一个**致命 bug**：
//
// mock 的 selftest 每跑一次就会创建一个会话并留在 sessions 里。之后官方客户端
// 做**登录前**的 `GET /passport/v1/user/onlineInfo`（不带任何凭据）时，兜底
// 逻辑把它匹配到了那个残留会话，返回 isOnline:true。
//
// 而客户端 `Me()` 的推进条件是：
//
//	return (already || (!nextService && !onlineInfo.isOnline)) && (yield an(), yield Ee());
//
// onlineInfo.isOnline 为 true ⇒ 条件为假 ⇒ **不执行 an()/Ee()** ⇒ 原生 agent
// 永远不被拉起 ⇒ 托盘 /v1/service/status 恒为 logout ⇒ 界面卡在「登录中」。
//
// 换句话说：mock 的"宽容"直接制造了一个真实网关不会出现的状态，污染了验证结论。
// 现在只做精确匹配：没凭据或凭据不认识，就是"没有会话"。
//
// ★ 凭据有两个来源，缺一不可（§24.10）：
//
//	Sid-Ticket 头  —— 原生 agent（Go-http-client）用它
//	cookie          —— 渲染层用它（浏览器自动携带；渲染层的请求体 token 恒为空）
func (s *Server) lookupSession(r *http.Request) (*session, bool) {
	tok := r.Header.Get("sid-ticket")
	if tok == "" {
		tok = r.Header.Get("sidTicket")
	}
	if tok == "" {
		if c, err := r.Cookie(cookieSidTicket); err == nil {
			tok = c.Value
		}
	}
	if tok == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[tok]
	return sess, ok
}

// route 是全局唯一的请求入口——所有请求都会先被完整记录，
// 包括我们**没有实现**的路径（这本身也是重要发现）。
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	s.record(r, body)

	path := r.URL.Path
	switch {
	case path == "/public/manifest":
		s.handleManifest(w, r)
	case path == "/public/manifest.js":
		s.handleManifestJS(w, r)
	case path == "/static/.portal.json":
		s.handlePortalInfo(w, r)
	case path == "/portal/theme/manifest.json":
		s.handleThemeManifest(w, r)
	case path == "/portal/theme/theme_skin.css":
		s.handleThemeCSS(w, r)
	case path == "/resource/client/getCopywriting":
		s.handleCopywriting(w, r)
	case path == "/passport/v1/public/authConfig":
		s.handleAuthConfig(w, r)
	case path == "/passport/v1/auth/psw":
		s.handlePsw(w, r)
	case path == "/passport/v1/public/sessionIdExchange":
		s.handleSessionIdExchange(w, r)
	case path == "/passport/v1/public/ticketExchange":
		s.handleTicketExchange(w, r)
	case path == "/passport/v1/auth/authCheck":
		s.handleAuthCheck(w, r)
	case path == "/passport/v1/auth/accessCheck":
		s.handleAccessCheck(w, r)
	case path == "/passport/v1/user/onlineInfo":
		s.handleOnlineInfo(w, r)
	case path == "/controller/v1/user/clientResource":
		s.handleClientResource(w, r)
	case path == "/controller/v1/public/events":
		s.handleEvents(w, r)
	case path == "/passport/v1/public/spaConfig":
		s.handleSpaConfig(w, r)
	case path == "/passport/v1/public/graphCheckCodePath":
		s.handleGraphCode(w, r)
	case path == "/controller/v1/public/antiMITMRequest":
		s.handleAntiMITM(w, r) // enable=0 时不应被调用；被调用即说明 mock 触发了新分支
	case path == "/passport/v1/user/logout":
		s.handleLogout(w, r)
	case strings.HasPrefix(path, "/portal/icon/"):
		s.handleIcon(w, r)
	default:
		s.logf("⚠ 未实现的路径: %s %s —— 已记录，可据此补实现", r.Method, path)
		s.replyJSON(w, map[string]any{
			"code":    10000004,
			"message": "not implemented in mock: " + path,
			"data":    map[string]any{},
		})
	}
}

func main() {
	var (
		addr    = flag.String("addr", "127.0.0.1:443", "监听地址（默认 443，与真实网关一致；改端口需在客户端填 https://127.0.0.1:<port>）")
		dataDir = flag.String("dir", ".", "密钥与证书存放目录")
		mitm    = flag.Int("mitm", 0, "antiMITMAttackData.enable：0=关闭（默认，与本机真实网关一致），1=开启以触发官方客户端的反中间人分支")
		verbose = flag.Bool("v", true, "打印完整请求（含 header/body）")
		// 手工覆盖 encryptedChallenge。默认留空 ⇒ 交给 fillAntiMITM 现算（§29）。
		challAnswer = flag.String("challenge-answer", "",
			"手工覆盖下发的 encryptedChallenge。默认留空=自动计算（§29）。仅供对照实验")
		// 实验开关：给所有 JSON 响应带上一个占位 X-Response-Sig，
		// 试图触发客户端打印它算出的 calcSig（见 §29.11）。
		respSig = flag.String("response-sig", "",
			"给所有响应带上 X-Response-Sig 占位值，用于逼出客户端的 calcSig 日志。默认不发该头")
		// events 长轮询：默认静默挂起，打开后触发一次 EvRclistUpdated。
		pushEv = flag.Bool("event", false,
			"启动后向 events 长轮询推送一次 EvRclistUpdated，用于验证客户端的事件分支")
	)
	flag.Parse()
	challengeAnswer = *challAnswer
	responseSigPlaceholder = *respSig

	abs, err := filepath.Abs(*dataDir)
	if err != nil {
		log.Fatalf("解析目录失败: %v", err)
	}

	rsaKey, existed, err := loadOrCreateRSA(abs)
	if err != nil {
		log.Fatalf("RSA 密钥: %v", err)
	}
	certPath, keyPath, created, err := loadOrCreateTLSCert(abs)
	if err != nil {
		log.Fatalf("TLS 证书: %v", err)
	}

	logPath := filepath.Join(abs, "requests.log")
	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatalf("打开日志: %v", err)
	}
	defer logF.Close()

	s := &Server{
		rsaKey:     rsaKey,
		guid:       newHex(32), // 64 hex，与真实网关一致
		unitID:     newUUID(),
		csrfToken:  newUUID(),
		mitmEnable: *mitm,
		sessions:   map[string]*session{},
		dataDir:    abs,
		eventWake:  make(chan struct{}, 1),
		logF:       logF,
		verbose:    *verbose,
	}

	// 恢复上一轮的会话：否则重启 mock 之后，客户端手里的旧 cookie
	// 会立刻失效，表现为"刷新失败"（10000004），掩盖真正在验证的问题。
	if n := s.loadSessions(); n > 0 {
		s.logf("已恢复 %d 个会话（重启后客户端无需重新登录）", n)
	}

	if existed {
		s.logf("已加载现有 RSA 私钥（跨重启稳定，客户端缓存的 authConfig 仍然有效）")
	} else {
		s.logf("已生成新的 RSA 私钥: %s", filepath.Join(abs, rsaKeyFile))
	}
	if created {
		s.logf("已生成自签 TLS 证书: %s", certPath)
	}
	s.logf("guid   = %s", s.guid)
	s.logf("unitid = %s", s.unitID)
	s.logf("mitmEnable = %d %s", s.mitmEnable, boolHint(s.mitmEnable == 1,
		"（将触发官方客户端的反中间人分支，可抓到 X-Request-Sig）", "（与本机真实网关一致，跳过反中间人）"))
	// 两道反中间人校验（§29）：算法已知，两个值都由 mock 现算，不再靠日志回读。
	if challengeAnswer == "" {
		s.logf("challenge = 自动应答模式（encryptedChallenge 与 mitmSig 每次现算）")
		s.logf("            → 客户端 checkChanllege / checkMITMAttackReqInvalid 都应通过")
	} else {
		s.logf("challenge = 手工覆盖，encryptedChallenge = %s", challengeAnswer)
		s.logf("            ⚠ 仅供对照实验：手工值会让 mitmSig 仍按自动值计算，两者不自洽")
	}

	// 响应验签（§29.11.2 的更正）：X-Response-Sig = HMAC-SHA256(signKey, 响应体原文)。
	//
	// mock 的 challenge 与设备公钥都是固定的，所以 signKey 也是固定的，
	// 启动时算一次即可，不必等 authConfig 被请求。
	signKeyFn = func() []byte {
		return signKeyFor(&antiMITMData{
			DevicePubKeyMod: fixedDevicePubKeyMod,
			DevicePubKeyExp: "10001",
			Challenge:       fixedChallenge,
		})
	}
	if responseSigPlaceholder != "" {
		s.logf("X-Response-Sig = 占位模式，值 = %s", responseSigPlaceholder)
		s.logf("            → 用于逼出客户端 calcSig 日志（§29.11），会破坏正常验签")
	} else {
		s.logf("X-Response-Sig = HMAC-SHA256(signKey, 响应体原文)，每条响应现算")
	}
	s.logf("请求日志: %s", logPath)

	// events 长轮询（§29.14）：默认静默挂起。
	if *pushEv {
		go func() {
			// 等客户端把轮询接上再推，否则事件会在没人监听时被消耗掉。
			time.Sleep(5 * time.Second)
			s.pushEvent("EvRclistUpdated")
			s.logf("events: 已推送一次 EvRclistUpdated")
		}()
		s.logf("events = 会在启动 5 秒后推送一次 EvRclistUpdated")
	} else {
		s.logf("events = 静默长轮询（挂起到 timeout 后返回空数组）")
	}
	s.logf("")
	s.logf("★ 在官方 aTrust 客户端里把接入地址改成: https://%s", *addr)
	s.logf("★ 然后用任意用户名/口令登录——mock 不校验真实凭证")
	s.logf("")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("加载 TLS 证书失败: %v", err)
	}

	srv := &http.Server{
		Addr:    *addr,
		Handler: http.HandlerFunc(s.route),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			// 官方客户端用 TLS 1.2/1.3；放宽 MinVersion 以兼容其 GM/TLS 探测
			MinVersion: tls.VersionTLS10,
		},
		ReadHeaderTimeout: 15 * time.Second,
	}

	s.logf("listening on https://%s …", *addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}

func boolHint(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
