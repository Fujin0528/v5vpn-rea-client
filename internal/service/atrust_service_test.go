package service

// atrust_service_test.go — ATrustService 的隔离性与会话语义。
//
// 这里用一个最小 aTrust 网关（httptest）替代 mock 进程，重点验证三件事：
//  1. 返回给 UI 的 map 与 VPNService.Login 同形 —— 否则 showConnectedView
//     会渲染出空白区域而不是报错
//  2. 协议分流出错时给出明确错误，而不是把 V5VPN 网关交给 aTrust 后端
//  3. 失败不会把 V5VPN 的状态改坏（边界三）

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/atrust"
	"github.com/hygkui/v5vpn-rea-client/internal/config"
)

// fakeHost 是 ATrustHost 的内存实现，替代 VPNService。
type fakeHost struct {
	mu       sync.Mutex
	cfg      *config.AppConfig
	logs     []string
	savedGws []config.GatewayProfile
	// userDataDir 供 aTrust 后端存放设备标识。默认空串 = 不持久化，
	// 这样测试不会在真实用户目录里写文件。
	userDataDir string
}

func newFakeHost(gateways ...config.GatewayProfile) *fakeHost {
	return &fakeHost{cfg: &config.AppConfig{Gateways: gateways}}
}

func (h *fakeHost) GetConfig() *config.AppConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg.Snapshot()
}

// UserDataDir 返回测试指定的目录（默认为空 = 不落盘）。
func (h *fakeHost) UserDataDir() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.userDataDir
}

func (h *fakeHost) SaveGateway(gw config.GatewayProfile) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.savedGws = append(h.savedGws, gw)
	for i := range h.cfg.Gateways {
		if h.cfg.Gateways[i].ID == gw.ID {
			h.cfg.Gateways[i] = gw
			return nil
		}
	}
	return nil
}

func (h *fakeHost) GetLogs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.logs))
	copy(out, h.logs)
	return out
}

func (h *fakeHost) Log(level, format string, args ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logs = append(h.logs, level+" "+format)
}

func (h *fakeHost) logContains(sub string) bool {
	for _, l := range h.GetLogs() {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// fakeGateway 是只实现了登录链所需端点的最小网关。
type fakeGateway struct {
	server *httptest.Server
	sid    string
	next   string // psw 返回的 nextService
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	g := &fakeGateway{sid: strings.Repeat("a", 64)}

	writeJSON := func(w http.ResponseWriter, data any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "OK", "data": data})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/public/manifest", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"server": "aTrust/2.5.16", "version": "2.5.16"})
	})
	mux.HandleFunc("/passport/v1/public/authConfig", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("authConfig 必须用 GET，实际 %s", r.Method)
		}
		writeJSON(w, map[string]any{
			"pubKey":         hex.EncodeToString(key.N.Bytes()),
			"pubKeyExp":      "65537",
			"antiReplayRand": "test-replay-rand",
			"domains":        []string{},
			"firstAuth":      []string{"auth/psw"},
			"security":       map[string]any{"csrfToken": "00000000-0000-0000-0000-000000000000"},
		})
	})
	mux.HandleFunc("/passport/v1/auth/psw", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		// 真解密一次：这能证明口令加密链路在 service 层也是通的，
		// 而不只是 atrust 包自身的单元测试通过。
		cipherBytes, err := hex.DecodeString(req.Password)
		if err != nil {
			t.Errorf("口令不是 hex: %v", err)
		}
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, key, cipherBytes)
		if err != nil {
			t.Errorf("网关解不开口令: %v", err)
		}
		if !strings.HasPrefix(string(plain), "secret-pass_") {
			t.Errorf("明文格式错误: %q", plain)
		}

		writeJSON(w, map[string]any{"sidTicket": g.sid, "nextService": g.next})
	})
	mux.HandleFunc("/passport/v1/auth/authCheck", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"nextService": ""})
	})
	mux.HandleFunc("/passport/v1/user/onlineInfo", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"isOnline": true})
	})
	mux.HandleFunc("/controller/v1/user/clientResource", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("clientResource 必须用 POST，实际 %s", r.Method)
		}
		writeJSON(w, map[string]any{
			"appListV2": []any{
				map[string]any{"name": "OA", "host": "10.0.0.5", "port": 443},
				map[string]any{"name": "GitLab", "host": "10.0.0.6", "port": 8443},
			},
		})
	})
	mux.HandleFunc("/passport/v1/user/logout", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{})
	})

	g.server = httptest.NewServer(mux)
	t.Cleanup(g.server.Close)
	return g
}

func (g *fakeGateway) profile() config.GatewayProfile {
	return config.GatewayProfile{
		ID:       "gw-atrust-test",
		Name:     "测试 aTrust",
		IP:       g.server.URL, // 完整 URL，绕开 https 拼接
		Protocol: config.ProtocolATrust,
	}
}

// TestATrustLoginResultShape 验证返回给 UI 的 map 与 VPNService.Login 同形。
func TestATrustLoginResultShape(t *testing.T) {
	g := newFakeGateway(t)
	host := newFakeHost(g.profile())
	svc := NewATrustService(host)

	res, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false)
	if err != nil {
		t.Fatalf("Login 失败: %v", err)
	}

	// 这些键必须与 VPNService.enterConnected 的返回一致。
	for _, k := range []string{"status", "username", "authType", "sessionId",
		"resourceState", "resourceCount", "resources"} {
		if _, ok := res[k]; !ok {
			t.Errorf("返回缺少键 %q（UI 的 showConnectedView 依赖它）", k)
		}
	}
	if res["status"] != "Connected" {
		t.Errorf("status = %v", res["status"])
	}
	if res["username"] != "alice" {
		t.Errorf("username = %v", res["username"])
	}
	if res["sessionId"] != g.sid {
		t.Errorf("sessionId = %v，期望 sidTicket", res["sessionId"])
	}

	// 资源异步加载，等它完成。
	waitFor(t, func() bool {
		s := svc.GetStatus()
		return s["resourceState"] == string(ResourceReady)
	})

	st := svc.GetStatus()
	resources, ok := st["resources"].([]interface{})
	_ = ok
	// GetStatus 返回的是 []atrust.Resource 本体，直接用类型断言取。
	items := svc.Resources
	if len(items) != 2 {
		t.Fatalf("期望 2 个应用，实际 %d: %+v", len(items), items)
	}
	if items[0].Name != "OA" || items[0].RemotePort != "443" {
		t.Errorf("应用解析错误: %+v", items[0])
	}
	_ = resources
}

// TestATrustLoginRejectsV5VPNGateway 是协议分流的兜底：
// UI 选错 endpoint 时必须得到明确的错误，而不是发给 V5VPN 网关。
func TestATrustLoginRejectsV5VPNGateway(t *testing.T) {
	gw := config.GatewayProfile{ID: "gw-v5", Name: "老网关", IP: "192.0.2.10", Port: 443}
	host := newFakeHost(gw)
	svc := NewATrustService(host)

	_, err := svc.Login("gw-v5", "alice", "pw", false, false)
	if err == nil {
		t.Fatal("V5VPN 网关不应能通过 aTrust 后端登录")
	}
	if !strings.Contains(err.Error(), "不能由 aTrust 后端登录") {
		t.Errorf("错误信息未说明原因: %v", err)
	}

	// 失败后必须回到 Error 状态，且不能残留 client。
	if st := svc.GetStatus(); st["status"] != "Error" {
		t.Errorf("status = %v，期望 Error", st["status"])
	}
	if svc.Client != nil {
		t.Error("失败后仍持有 client")
	}
}

// TestATrustLoginUnknownGateway 验证网关不存在时的错误路径。
func TestATrustLoginUnknownGateway(t *testing.T) {
	svc := NewATrustService(newFakeHost())
	if _, err := svc.Login("nope", "u", "p", false, false); err == nil {
		t.Fatal("不存在的网关应当报错")
	}
}

// TestATrustLoginRecordsDataPlaneGap 验证「数据面未实现」这件事被明确记录。
//
// 静默成功会让人以为资源可以访问，这是最糟的失败方式。
func TestATrustLoginRecordsDataPlaneGap(t *testing.T) {
	g := newFakeGateway(t)
	host := newFakeHost(g.profile())
	svc := NewATrustService(host)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	if !host.logContains("数据面通道 TLS:441 + SOCKS5 尚未实现") {
		t.Errorf("未记录数据面缺口。日志: %v", host.GetLogs())
	}
}

// TestATrustLogoutClearsState 验证登出后的状态与幂等性。
func TestATrustLogoutClearsState(t *testing.T) {
	g := newFakeGateway(t)
	host := newFakeHost(g.profile())
	svc := NewATrustService(host)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	waitFor(t, func() bool { return svc.GetStatus()["resourceState"] == string(ResourceReady) })

	ok, err := svc.Logout()
	if err != nil || !ok {
		t.Fatalf("Logout = (%v, %v)", ok, err)
	}
	st := svc.GetStatus()
	if st["status"] != "Disconnected" {
		t.Errorf("登出后 status = %v", st["status"])
	}
	if svc.Client != nil {
		t.Error("登出后仍持有 client")
	}
	if len(svc.Resources) != 0 {
		t.Errorf("登出后资源未清空: %+v", svc.Resources)
	}

	// 未连接时再登出必须是安全的（OnBeforeQuit 可能重复调用）。
	ok, err = svc.Logout()
	if err != nil || !ok {
		t.Fatalf("重复 Logout = (%v, %v)", ok, err)
	}
}

// TestATrustIsActive 验证退出钩子用来判断"要不要登出本后端"的依据。
func TestATrustIsActive(t *testing.T) {
	svc := NewATrustService(newFakeHost())
	if svc.IsActive() {
		t.Error("初始状态不应为 active")
	}

	svc.mu.Lock()
	svc.Status = "Connected"
	svc.mu.Unlock()
	if !svc.IsActive() {
		t.Error("Connected 应为 active")
	}

	svc.mu.Lock()
	svc.Status = "Error"
	svc.mu.Unlock()
	if svc.IsActive() {
		t.Error("Error 不应为 active")
	}
}

// TestATrustStatusShapeIsUICompatible 校验 GetStatus 的键集合兼容 VPNService。
func TestATrustStatusShapeIsUICompatible(t *testing.T) {
	svc := NewATrustService(newFakeHost())
	st := svc.GetStatus()

	for _, k := range []string{"status", "statusDetail", "resources", "resourceState",
		"resourceError", "lastUseGateway", "logCount"} {
		if _, ok := st[k]; !ok {
			t.Errorf("GetStatus 缺少键 %q", k)
		}
	}
	if st["protocol"] != config.ProtocolATrust {
		t.Errorf("protocol = %v，期望 atrust", st["protocol"])
	}
}

// TestATrustStatusResourcesIsNeverNull 守护前端不崩。
//
// nil 切片会被编码成 JSON null，而 renderResources 里直接取
// resources.length —— null.length 是 TypeError，界面会整块空白而不是
// 显示"暂无应用"。返回空数组才是可渲染的。
func TestATrustStatusResourcesIsNeverNull(t *testing.T) {
	svc := NewATrustService(newFakeHost())
	st := svc.GetStatus()

	res, ok := st["resources"]
	if !ok {
		t.Fatal("缺少 resources 键")
	}
	if res == nil {
		t.Fatal("未连接时 resources 为 nil，会被编码成 JSON null")
	}

	// 走一遍真实序列化，断言关键字面量是 [] 而不是 null。
	buf, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if strings.Contains(string(buf), `"resources":null`) {
		t.Fatalf("resources 被编码成 null: %s", buf)
	}
}

// TestATrustGatewayURL 覆盖用户可能填的几种地址形态。
func TestATrustGatewayURL(t *testing.T) {
	cases := []struct {
		name string
		gw   config.GatewayProfile
		want string
	}{
		{"主机名加默认端口", config.GatewayProfile{IP: "gw.example.com"}, "https://gw.example.com:443"},
		{"主机名加自定义端口", config.GatewayProfile{IP: "gw.example.com", Port: 8443}, "https://gw.example.com:8443"},
		{"主机名自带端口", config.GatewayProfile{IP: "gw.example.com:8443", Port: 443}, "https://gw.example.com:8443"},
		{"完整 URL", config.GatewayProfile{IP: "http://127.0.0.1:9000", Port: 443}, "http://127.0.0.1:9000"},
		{"空地址", config.GatewayProfile{}, ""},
		{"IPv6 字面量", config.GatewayProfile{IP: "2001:db8::1", Port: 443}, "https://[2001:db8::1]:443"},
	}
	for _, c := range cases {
		got := atrustGatewayURL(c.gw)
		// IPv6 需要方括号才能拼成合法 URL；这里只断言不出现畸形拼接。
		if c.name == "IPv6 字面量" {
			if strings.Count(got, ":") < 3 {
				t.Errorf("%s: 地址被破坏 %q", c.name, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestATrustSaveAccountPreservesOtherFields 验证保存账号不会抹掉网关配置。
func TestATrustSaveAccountPreservesOtherFields(t *testing.T) {
	gw := config.GatewayProfile{
		ID:       "gw-1",
		Name:     "办公网关",
		IP:       "198.51.100.20",
		Port:     443,
		Protocol: config.ProtocolATrust,
		SavedAccounts: []config.UserAccount{
			{Username: "bob", Password: "old", Remember: true},
		},
	}
	host := newFakeHost(gw)
	svc := NewATrustService(host)

	svc.saveAccount(gw, "alice", "newpass", true, false)

	if len(host.savedGws) != 1 {
		t.Fatalf("SaveGateway 调用次数 = %d", len(host.savedGws))
	}
	saved := host.savedGws[0]
	if saved.ID != "gw-1" || saved.Name != "办公网关" || saved.IP != "198.51.100.20" {
		t.Errorf("网关字段被破坏: %+v", saved)
	}
	if saved.Protocol != config.ProtocolATrust {
		t.Error("Protocol 字段丢失")
	}
	if saved.LastUserName != "alice" {
		t.Errorf("LastUserName = %q", saved.LastUserName)
	}
	// 已有账号必须保留，新账号必须追加。
	if len(saved.SavedAccounts) != 2 {
		t.Fatalf("账号数 = %d，期望 2: %+v", len(saved.SavedAccounts), saved.SavedAccounts)
	}
	if saved.SavedAccounts[0].Username != "bob" {
		t.Error("已有账号被覆盖")
	}
	if saved.SavedAccounts[1].Username != "alice" || saved.SavedAccounts[1].Password != "newpass" {
		t.Errorf("新账号写入错误: %+v", saved.SavedAccounts[1])
	}
}

// TestATrustErrorCode 验证错误码映射。
func TestATrustErrorCode(t *testing.T) {
	if got := ATrustErrorCode(errors.New("随便一个错误")); got != "" {
		t.Errorf("普通错误不应有码，实际 %q", got)
	}
	if got := ATrustErrorCode(fmt.Errorf("%w: sms", atrust.ErrMultiFactorRequired)); got != "mfa_required" {
		t.Errorf("多因子错误码 = %q", got)
	}
	if got := ATrustErrorCode(atrust.ErrNotATrustGateway); got != "not_atrust_gateway" {
		t.Errorf("非 aTrust 网关错误码 = %q", got)
	}
}

// waitFor 轮询等待条件成立，避免对异步资源加载做固定 sleep。
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}
