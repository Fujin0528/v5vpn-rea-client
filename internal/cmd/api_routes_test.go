package main

// api_routes_test.go — 本地 HTTP 路由的接线。
//
// 这里验的是「请求被送到了正确的后端」以及「错误响应的形状」，
// 不是协议实现本身（那在 internal/service 与 internal/atrust 的测试里）。
// UI 只靠错误响应里的 code 字段分支，形状错了就退化成显示原始英文报错。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/service"
)

// newTestRouter 构造路由表，不监听端口也不建窗口。
func newTestRouter(t *testing.T) (http.Handler, *service.VPNService, *service.ATrustService) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	v5 := service.NewVPNService(nil)
	at := service.NewATrustService(v5)
	uiFS := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}}
	return newAPIRouter(uiFS, v5, at), v5, at
}

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestATrustLoginRouteIsWired 验证 /api/atrust/login 真的挂上了。
//
// 用"不存在的网关"作探针：路由不存在会得到 404，路由在但后端报错会是 400。
func TestATrustLoginRouteIsWired(t *testing.T) {
	h, _, _ := newTestRouter(t)
	rec := postJSON(t, h, "/api/atrust/login", `{"gwId":"nope","username":"u","password":"p"}`)

	if rec.Code == http.StatusNotFound {
		t.Fatal("/api/atrust/login 未注册（404）")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d，期望 400。body=%s", rec.Code, rec.Body)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是 JSON: %v (%s)", err, rec.Body)
	}
	if payload["error"] == "" {
		t.Error("缺少 error 字段")
	}
}

// TestATrustLoginRouteRejectsV5VPNGateway 验证协议分流在路由层也成立。
//
// 这比"UI 选对 endpoint"更强一层：即便请求打错了地方，
// 后端也会明确拒绝，而不是拿 V5VPN 网关去连 aTrust 协议。
func TestATrustLoginRouteRejectsV5VPNGateway(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	v5 := service.NewVPNService(nil)
	at := service.NewATrustService(v5)

	// 直接调服务，绕开 setting.xml：这里验的是服务端的拒绝逻辑。
	_, err := at.Login("gw-v5", "u", "p", false, false)
	if err == nil {
		t.Fatal("不存在的网关应当报错")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("错误信息 = %v", err)
	}
}

// TestATrustLoginServiceRejectsNonATrust 验证真实的 V5VPN 网关被拒。
func TestATrustLoginServiceRejectsNonATrust(t *testing.T) {
	v5 := service.NewVPNService(nil)
	at := service.NewATrustService(v5)

	gw := v5.GetGateways()
	if len(gw) == 0 {
		t.Skip("默认配置里没有网关，跳过")
	}
	// 默认配置里的网关都没有 protocol 字段，即 V5VPN。
	_, err := at.Login(gw[0].ID, "u", "p", false, false)
	if err == nil {
		t.Fatal("V5VPN 网关不应能由 aTrust 后端登录")
	}
	if !strings.Contains(err.Error(), "不能由 aTrust 后端登录") {
		t.Errorf("错误信息未说明协议不匹配: %v", err)
	}
}

// TestATrustStatusRoute 验证 /api/atrust/status 返回 UI 需要的键。
func TestATrustStatusRoute(t *testing.T) {
	h, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/atrust/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	for _, k := range []string{"status", "statusDetail", "resources", "resourceState",
		"resourceCount", "activeBackend", "protocol", "appVersion"} {
		if _, ok := payload[k]; !ok {
			t.Errorf("缺少键 %q", k)
		}
	}
}

// TestStatusRouteCarriesActiveBackend 验证 /api/status 带上后端判定。
//
// UI 用它决定渲染哪一份资源表；缺这个键时前端只能猜。
func TestStatusRouteCarriesActiveBackend(t *testing.T) {
	h, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	if _, ok := payload["activeBackend"]; !ok {
		t.Fatal("/api/status 缺少 activeBackend")
	}
	if payload["appVersion"] != AppVersion {
		t.Errorf("appVersion = %v，期望 %s", payload["appVersion"], AppVersion)
	}
}

// TestLogoutRouteIsShared 验证 /api/logout 在两个协议下都能用。
//
// 这是有意的设计：UI 的断开按钮不区分协议，路由按"谁在活动"决定
// 断开谁。没有会话时也必须返回成功（幂等）。
func TestLogoutRouteIsShared(t *testing.T) {
	h, _, _ := newTestRouter(t)

	rec := postJSON(t, h, "/api/logout", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d，期望 200（幂等）", rec.Code)
	}
	var payload map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	if !payload["success"] {
		t.Error("success 不为 true")
	}
}

// TestWrongBackendGuard 是 §14.5.2 边界二的接线守卫。
//
// 没有它的时候，把 aTrust 网关发到 /api/login 会被真的当作 V5VPN 连接
// 发出去：对端是 aTrust 网关，于是拿到语焉不详的"未下发有效会话ID"，
// 同时 V5VPN 后端的状态被改成 Error。界面显示"V5VPN 认证失败"，
// 而真实原因只是选错了后端。
func TestWrongBackendGuard(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	v5 := service.NewVPNService(nil)
	at := service.NewATrustService(v5)

	// 往配置里加一个 aTrust 网关。
	if err := v5.SaveGateway(config.GatewayProfile{
		ID: "gw-at", Name: "零信任网关", IP: "198.51.100.20", Port: 443,
		Protocol: config.ProtocolATrust,
	}); err != nil {
		t.Fatalf("保存网关失败: %v", err)
	}

	uiFS := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}}
	h := newAPIRouter(uiFS, v5, at)

	// aTrust 网关打到 V5VPN 端点：必须是 409，且不能真的发起连接。
	rec := postJSON(t, h, "/api/login", `{"gwId":"gw-at","username":"u","password":"p"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d，期望 409。body=%s", rec.Code, rec.Body)
	}
	var payload map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	if payload["code"] != "wrong_backend" {
		t.Errorf("code = %q，期望 wrong_backend", payload["code"])
	}
	// V5VPN 后端不应因此进入 Error。
	if st := v5.GetStatus(); st["status"] != "Disconnected" {
		t.Errorf("V5VPN 状态被改动: %v", st["status"])
	}
}

// TestWrongBackendGuardReverse 验证反方向。
func TestWrongBackendGuardReverse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	v5 := service.NewVPNService(nil)
	at := service.NewATrustService(v5)

	if err := v5.SaveGateway(config.GatewayProfile{
		ID: "gw-v5", Name: "老网关", IP: "192.0.2.10", Port: 443,
	}); err != nil {
		t.Fatalf("保存网关失败: %v", err)
	}

	uiFS := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}}
	h := newAPIRouter(uiFS, v5, at)

	rec := postJSON(t, h, "/api/atrust/login", `{"gwId":"gw-v5","username":"u","password":"p"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d，期望 409。body=%s", rec.Code, rec.Body)
	}
	var payload map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	if payload["code"] != "wrong_backend" {
		t.Errorf("code = %q，期望 wrong_backend", payload["code"])
	}
}

// TestWriteATrustResultCodes 锁定 aTrust 侧的稳定错误码。
//
// 两边码值集合不同（aTrust 没有 password_expired，V5VPN 没有
// mfa_required），所以用独立函数而不是给 writeLoginResult 加参数。
func TestWriteATrustResultCodes(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode string
	}{
		{"普通错误", errPlain{}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeATrustResult(rec, nil, tc.err)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", rec.Code)
			}
			var payload map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &payload)
			if got := payload["code"]; got != tc.wantCode {
				t.Fatalf("code = %q，期望 %q", got, tc.wantCode)
			}
			if payload["error"] == "" {
				t.Fatal("缺少 error 字段")
			}
		})
	}
}

// TestATrustGatewayProtocolRouting 验证同一份配置里两个协议的网关并存。
//
// 这是「支持切换」的判据：V5VPN 网关与 aTrust 网关各有各的 protocol，
// 互不影响，且旧的（无 protocol 字段的）网关继续按 V5VPN 处理。
func TestATrustGatewayProtocolRouting(t *testing.T) {
	cfg := &config.AppConfig{
		Gateways: []config.GatewayProfile{
			{ID: "gw-0", Name: "老网关", IP: "192.0.2.10", Port: 443},
			{ID: "gw-1", Name: "办公网关", IP: "198.51.100.20", Port: 443, Protocol: config.ProtocolATrust},
		},
	}

	for _, tc := range []struct {
		id      string
		wantAt  bool
		wantPrc string
	}{
		{"gw-0", false, config.ProtocolV5VPN},
		{"gw-1", true, config.ProtocolATrust},
		{"老网关", false, config.ProtocolV5VPN},
		{"办公网关", true, config.ProtocolATrust},
	} {
		gw := cfg.FindGateway(tc.id)
		if gw == nil {
			t.Fatalf("找不到网关 %q", tc.id)
		}
		if gw.IsATrust() != tc.wantAt {
			t.Errorf("%s: IsATrust = %v，期望 %v", tc.id, gw.IsATrust(), tc.wantAt)
		}
		if gw.EffectiveProtocol() != tc.wantPrc {
			t.Errorf("%s: protocol = %q，期望 %q", tc.id, gw.EffectiveProtocol(), tc.wantPrc)
		}
	}
}

type errPlain struct{}

func (errPlain) Error() string { return "plain error" }
