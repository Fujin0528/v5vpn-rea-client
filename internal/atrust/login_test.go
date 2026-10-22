package atrust

// login_test.go — 用 httptest 模拟网关，验证整条登录链的分支与约束。
//
// 这不是"再测一遍 happy path"：每个用例对应一条**实测踩过或明确禁止**
// 的行为，比如 nextService 拼错、txoken 为空、ticketExchange 返回空票。
// 把这些约束钉死在测试里，可以防止将来"顺手简化"时把坑重新挖回来。

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeGateway 是一个最小可用的 aTrust 网关，行为按规范实现。
type fakeGateway struct {
	key *rsa.PrivateKey

	// 可调开关，用于构造异常场景。
	nextService       string // psw 返回的 nextService
	authCheckNext     string // authCheck 返回的 nextService
	ticketReturnsSid  bool   // ticketExchange 是否返回 sidTicket
	serverField       string // manifest 的 server 字段
	omitAuthCheckCols bool   // authCheck 是否省略 ACL 列
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	return &fakeGateway{
		key:              key,
		nextService:      "auth/authCheck",
		ticketReturnsSid: true,
		serverField:      "Sangfor aTrust Gateway",
	}
}

func (g *fakeGateway) handler() http.Handler {
	mux := http.NewServeMux()

	// manifest —— 识别网关类型
	mux.HandleFunc(pathManifest, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Envelope[Manifest]{Code: 0, Message: "成功", Data: Manifest{
			Server:     g.serverField,
			Version:    "2.5.16",
			Capacities: map[string]any{"antiMIMTAttack": map[string]any{"version": ""}},
		}})
	})

	// manifest.js —— 必须是 JS，不是 JSON
	mux.HandleFunc(pathManifestJS, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(
			`var entranceConfig = {"entrance":{"type":"portal","i18nVersionType":"cn"},"aioClient":{"enable":true}};`))
	})

	// authConfig —— GET 返回 35 键平铺
	mux.HandleFunc(pathAuthConfig, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			// POST 是另一条通道，data 恒为空。故意这样实现以固化差异。
			writeJSON(w, Envelope[map[string]any]{Code: 0, Message: "成功", Data: map[string]any{}})
			return
		}
		writeJSON(w, Envelope[AuthConfig]{Code: 0, Message: "成功", Data: AuthConfig{
			FirstAuth:             []string{"auth/psw"},
			DefaultDomain:         "local",
			Domains:               []string{"local"},
			PubKey:                hex.EncodeToString(g.key.N.Bytes()),
			PubKeyExp:             "65537",
			AntiReplayRand:        "0123456789abcdef",
			ClientVerifyCode:      "20911cd7-22ae-4c45-8e10-41f31eb49199",
			ClientInstallMode:     "force",
			EnableClientAutoStart: "0",
			GUID:                  strings.Repeat("a", 64),
			UnitID:                "6c3788db-5150-4b23-8348-ba2108b29d3c",
			Security: struct {
				CSRFToken string `json:"csrfToken"`
			}{CSRFToken: "430d5bd4-fa70-42f4-b373-3070deff1915"},
			AntiMITMAttackData: AntiMITMData{Enable: 0},
			CertDomains:        []string{},
			CertPort:           "6660",
			TLSConfig:          14,
		}})
	})

	// psw —— 解密口令，验证明文格式
	mux.HandleFunc(pathPSW, func(w http.ResponseWriter, r *http.Request) {
		var req PSWRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, Envelope[any]{Code: 10000004, Message: "参数错误"})
			return
		}

		// 解密并校验 "<password>_<antiReplayRand>" 格式。
		plain, err := decryptChunks(g.key, req.Password)
		if err != nil {
			writeJSON(w, Envelope[any]{Code: 10000004, Message: "口令密文无法解密"})
			return
		}
		if !strings.HasSuffix(plain, "_0123456789abcdef") {
			writeJSON(w, Envelope[any]{Code: 10000004, Message: "尾部 antiReplayRand 不匹配: " + plain})
			return
		}

		// 下发会话 cookie —— 这是登录链能继续的前提（§24.10）。
		http.SetCookie(w, &http.Cookie{
			Name: cookieSidTicket, Value: strings.Repeat("b", 64), Path: "/",
			Secure: true, SameSite: http.SameSiteNoneMode,
		})

		writeJSON(w, Envelope[PSWResponse]{Code: 0, Message: "成功", Data: PSWResponse{
			SidTicket:   strings.Repeat("b", 64),
			NextService: g.nextService,
		}})
	})

	// authCheck —— nextService 置空以触发客户端拉起 agent
	mux.HandleFunc(pathAuthCheck, func(w http.ResponseWriter, r *http.Request) {
		if !hasSessionCookie(r) {
			writeJSON(w, Envelope[any]{Code: 10000003, Message: "会话无效"})
			return
		}
		d := AuthCheckData{NextService: g.authCheckNext, SidTicket: strings.Repeat("b", 64)}
		if !g.omitAuthCheckCols {
			d.ActionType, d.Action, d.PolicyID, d.Reason = "allow", "allow", "1", "ok"
		}
		writeJSON(w, Envelope[AuthCheckData]{Code: 0, Message: "成功", Data: d})
	})

	mux.HandleFunc(pathAccessCheck, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Envelope[AuthCheckData]{Code: 0, Message: "成功", Data: AuthCheckData{}})
	})

	// onlineInfo —— 未登录时必须是 code:0 + isOnline:false
	mux.HandleFunc(pathOnlineInfo, func(w http.ResponseWriter, r *http.Request) {
		if !hasSessionCookie(r) {
			writeJSON(w, Envelope[OnlineInfo]{Code: 0, Message: "成功", Data: OnlineInfo{IsOnline: false}})
			return
		}
		writeJSON(w, Envelope[OnlineInfo]{Code: 0, Message: "成功", Data: OnlineInfo{IsOnline: true}})
	})

	mux.HandleFunc(pathClientResource, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Envelope[map[string]any]{Code: 0, Message: "成功", Data: map[string]any{
			"resource": []any{map[string]any{"name": "intranet", "host": "10.0.0.1", "port": 80}},
		}})
	})

	mux.HandleFunc(pathSessionExch, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, Envelope[any]{Code: 10000004, Message: "表单解析失败"})
			return
		}
		sid := r.PostFormValue("sidTicket")
		http.SetCookie(w, &http.Cookie{
			Name: cookieSidTicket, Value: sid, Path: "/", Secure: true, SameSite: http.SameSiteNoneMode,
		})
		writeJSON(w, Envelope[SessionExchange]{Code: 0, Message: "成功", Data: SessionExchange{SessionID: sid}})
	})

	mux.HandleFunc(pathTicketExch, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, Envelope[any]{Code: 10000004, Message: "表单解析失败"})
			return
		}
		se := SessionExchange{}
		if g.ticketReturnsSid {
			se.SidTicket = strings.Repeat("b", 64)
		}
		writeJSON(w, Envelope[SessionExchange]{Code: 0, Message: "成功", Data: se})
	})

	mux.HandleFunc(pathLogout, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Envelope[map[string]any]{Code: 0, Message: "成功", Data: map[string]any{}})
	})

	return mux
}

// start 启动 TLS 服务（aTrust 控制面只有 HTTPS）。
func (g *fakeGateway) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(g.handler())
	t.Cleanup(srv.Close)
	return srv
}

// newClientFor 为新起的网关建客户端，跳过自签证书校验。
func newClientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(srv.URL, Options{
		InsecureSkipVerify: true,
		Logf:               func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewClient 失败: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// ---------- 测试 ----------

func TestLoginHappyPath(t *testing.T) {
	g := newFakeGateway(t)
	c := newClientFor(t, g.start(t))

	res, err := c.Login(context.Background(), "alice", "hunter2")
	if err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	if res.SidTicket != strings.Repeat("b", 64) {
		t.Fatalf("sidTicket = %q", res.SidTicket)
	}
	if res.Resources == nil {
		t.Fatal("资源树为空")
	}
	if _, ok := res.Resources["resource"]; !ok {
		t.Fatalf("资源树里没有 resource 键: %v", res.Resources)
	}
}

func TestLoginRejectsUnknownNextService(t *testing.T) {
	// §24.3：拼错的 nextService 会让客户端静默走完，界面永远停在"登录中"。
	// 我们选择在本地直接报错，让问题以一个明确的错误暴露。
	g := newFakeGateway(t)
	g.nextService = "auth/checkAccess" // 形似但不在分发表内
	c := newClientFor(t, g.start(t))

	_, err := c.Login(context.Background(), "alice", "hunter2")
	if err == nil {
		t.Fatal("期望因为 nextService 报错，实际成功")
	}
	if !strings.Contains(err.Error(), "nextService") {
		t.Fatalf("错误信息没提到 nextService: %v", err)
	}
}

func TestLoginAcceptsEmptyNextService(t *testing.T) {
	// 空串是合法的：表示没有下一步。
	g := newFakeGateway(t)
	g.nextService = ""
	c := newClientFor(t, g.start(t))

	if _, err := c.Login(context.Background(), "alice", "hunter2"); err != nil {
		t.Fatalf("空 nextService 应当成功: %v", err)
	}
}

func TestLoginAcceptsAccessCheckBranch(t *testing.T) {
	g := newFakeGateway(t)
	g.nextService = "auth/accessCheck"
	c := newClientFor(t, g.start(t))

	if _, err := c.Login(context.Background(), "alice", "hunter2"); err != nil {
		t.Fatalf("accessCheck 分支应当成功: %v", err)
	}
}

func TestLoginDetectsMultiFactor(t *testing.T) {
	g := newFakeGateway(t)
	g.authCheckNext = "auth/sms" // authCheck 还要继续
	c := newClientFor(t, g.start(t))

	_, err := c.Login(context.Background(), "alice", "hunter2")
	if !IsMultiFactorRequired(err) {
		t.Fatalf("期望 ErrMultiFactorRequired，得到 %v", err)
	}
}

func TestTicketExchangeRejectsEmptySid(t *testing.T) {
	// 客户端会读 data.sidTicket；返回空串必须报错而不是把空值传下去。
	g := newFakeGateway(t)
	g.ticketReturnsSid = false
	c := newClientFor(t, g.start(t))

	ctx := context.Background()
	if err := c.Detect(ctx); err != nil {
		t.Fatalf("Detect 失败: %v", err)
	}
	if _, err := c.FetchAuthConfig(ctx); err != nil {
		t.Fatalf("FetchAuthConfig 失败: %v", err)
	}
	if _, err := c.LoginWithPassword(ctx, "alice", "hunter2"); err != nil {
		t.Fatalf("LoginWithPassword 失败: %v", err)
	}

	if _, err := c.TicketExchange(ctx, ""); err == nil {
		t.Fatal("ticketExchange 返回空 sidTicket 时应当报错")
	}
}

func TestDetectRejectsNonATrustGateway(t *testing.T) {
	g := newFakeGateway(t)
	g.serverField = "some other vpn"
	c := newClientFor(t, g.start(t))

	err := c.Detect(context.Background())
	if !IsNotATrustGateway(err) {
		t.Fatalf("期望 ErrNotATrustGateway，得到 %v", err)
	}
}

func TestDetectAcceptsATrustGateway(t *testing.T) {
	g := newFakeGateway(t)
	c := newClientFor(t, g.start(t))
	if err := c.Detect(context.Background()); err != nil {
		t.Fatalf("Detect 失败: %v", err)
	}
}

func TestEntranceConfigParsesJavaScript(t *testing.T) {
	// §22.2：manifest.js 返回的是 JS，需要提取其中的 JSON 字面量。
	g := newFakeGateway(t)
	c := newClientFor(t, g.start(t))

	m, err := c.EntranceConfig(context.Background())
	if err != nil {
		t.Fatalf("EntranceConfig 失败: %v", err)
	}
	entrance, ok := m["entrance"].(map[string]any)
	if !ok {
		t.Fatalf("entrance 不是对象: %v", m)
	}
	if entrance["type"] != "portal" {
		t.Fatalf("entrance.type = %v，期望 portal", entrance["type"])
	}
}

func TestOnlineInfoAnonymousIsNotAnError(t *testing.T) {
	// §24.4：未登录时 isOnline=false 且 code=0，这是正常答案。
	g := newFakeGateway(t)
	c := newClientFor(t, g.start(t))

	info, err := c.OnlineInfo(context.Background())
	if err != nil {
		t.Fatalf("匿名 onlineInfo 不应报错: %v", err)
	}
	if info.IsOnline {
		t.Fatal("未登录时 isOnline 应为 false")
	}
}

func TestSessionIDExchangeInstallsCookie(t *testing.T) {
	// §24.14：sessionIdExchange 之后必须能靠 cookie 认回会话，
	// 因为 agent 的后续请求既不带头也不带显式凭据。
	g := newFakeGateway(t)
	c := newClientFor(t, g.start(t))

	ctx := context.Background()
	if _, err := c.FetchAuthConfig(ctx); err != nil {
		t.Fatalf("FetchAuthConfig 失败: %v", err)
	}
	if _, err := c.LoginWithPassword(ctx, "alice", "hunter2"); err != nil {
		t.Fatalf("LoginWithPassword 失败: %v", err)
	}
	if _, err := c.SessionIDExchange(ctx, ""); err != nil {
		t.Fatalf("SessionIDExchange 失败: %v", err)
	}

	// 新建一个不带显式头的请求路径：ClientResource 只有 cookie 可用
	// （我们的实现会额外带 Sid-Ticket 头，但 cookie 必须也在）。
	hasCookie := false
	for _, ck := range c.http.Jar.Cookies(mustParse(t, c.BaseURL())) {
		if ck.Name == cookieSidTicket && ck.Value == strings.Repeat("b", 64) {
			hasCookie = true
		}
	}
	if !hasCookie {
		t.Fatal("sessionIdExchange 后 cookie jar 里没有 sidTicket")
	}
}

func TestLogoutClearsSession(t *testing.T) {
	g := newFakeGateway(t)
	c := newClientFor(t, g.start(t))

	ctx := context.Background()
	if _, err := c.Login(ctx, "alice", "hunter2"); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	if c.SidTicket() == "" {
		t.Fatal("登录后 sidTicket 为空")
	}

	if err := c.LogoutAndClear(ctx); err != nil {
		t.Fatalf("LogoutAndClear 失败: %v", err)
	}
	if c.SidTicket() != "" {
		t.Fatal("登出后 sidTicket 未清空")
	}
	if c.AuthConfig() != nil {
		t.Fatal("登出后 authConfig 未清空")
	}
}

// ---------- 辅助 ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func hasSessionCookie(r *http.Request) bool {
	ck, err := r.Cookie(cookieSidTicket)
	return err == nil && ck.Value != ""
}

func mustParse(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("解析 URL 失败: %v", err)
	}
	return u
}

// decryptChunks 是网关侧的解密：按块长切分密文，逐块 PKCS#1 v1.5 解开。
func decryptChunks(key *rsa.PrivateKey, cipherHex string) (string, error) {
	blockLen := key.Size() * 2
	if len(cipherHex)%blockLen != 0 {
		return "", errors.New("密文长度不是块长的整数倍")
	}
	var out strings.Builder
	for i := 0; i < len(cipherHex); i += blockLen {
		block, err := hex.DecodeString(cipherHex[i : i+blockLen])
		if err != nil {
			return "", err
		}
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, key, block)
		if err != nil {
			return "", err
		}
		out.Write(plain)
	}
	return out.String(), nil
}
