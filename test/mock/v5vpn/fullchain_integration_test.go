package mockserver

// 全链（full-chain）模式的协议对撞测试：一条链上走完所有挑战——
//   - 裸口令 -> 0x80 图形验证码挑战（验证码是口令请求的字段，无独立端点）
//   - 带码重发口令 -> code 2 证书挑战
//   - 证书因子 -> code 8 短信挑战
//   - 短信码 -> code 4 令牌挑战
//   - 令牌码 -> code 0 建立会话
//   - FetchIntegration 拉取内网资源
//
// 这是网关驱动状态机的极端验收：跳数最多、每一步都是网关结果码驱动，
// 挑战会话全程同一个 VSG_SESSIONID。UI 侧对应 E2E 场景 11（四个模态
// 连续替换）。

import (
	"errors"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func TestMockServerFullChain(t *testing.T) {
	srv, host, port := startTestGateway(t, ModeFullChain)

	client := protocol.NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("["+level+"] "+format, args...)
	})
	if _, err := client.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	clientCert, _, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// 1. The bare password is answered with the captcha challenge.
	if _, err := client.AuthPassword("admin", "admin123", ""); !isVerifyCodeChallenge(t, err) {
		t.Fatalf("expected the captcha challenge on the bare password, got %v", err)
	}

	// 2. The captcha image binds its code to this session; the code rides the
	// password request, so the login is re-sent with it.
	if _, _, err := client.FetchVerifyCode(); err != nil {
		t.Fatalf("FetchVerifyCode failed: %v", err)
	}
	srv.mu.RLock()
	captcha := srv.currentVerifyCode
	srv.mu.RUnlock()
	if captcha == "" {
		t.Fatal("mock did not generate a captcha code")
	}

	// 3. Password(+captcha) -> cert -> SMS: the two-step call surfaces the SMS
	// challenge with the certificate factor reported as presented.
	resp, err := client.AuthPasswordWithCert(&clientCert, "admin", "admin123", captcha)
	if !protocol.IsSMSChallenge(err) {
		t.Fatalf("expected the SMS challenge after the certificate factor, got %v", err)
	}
	if resp == nil || !resp.CertFactorUsed {
		t.Fatalf("certificate factor not reported on the challenged chain: %+v", resp)
	}
	if client.SessionID == "" {
		t.Fatal("challenge response did not yield a session the codes must bind to")
	}

	// 4. SMS: deliver, fail once (0x10A keeps the challenge), then pass — the
	// gateway answers the token challenge (code 4).
	if err := client.SendSMC(); err != nil {
		t.Fatalf("SendSMC failed: %v", err)
	}
	if _, err := client.AuthSMC("000000"); !protocol.IsSMCCodeError(err) {
		t.Fatalf("expected 0x10A for a wrong SMS code, got %v", err)
	}
	if _, err := client.AuthSMC(srv.currentSMSCodeForTest()); !protocol.IsTokenChallenge(err) {
		t.Fatalf("expected the token challenge after the SMS factor, got %v", err)
	}

	// 5. Token: fail once (0x109 keeps the challenge), then complete.
	if _, err := client.AuthToken("000000"); !protocol.IsTokenCodeError(err) {
		t.Fatalf("expected 0x109 for a wrong token code, got %v", err)
	}
	if client.IsLoggedIn() {
		t.Fatal("a wrong code must not log the session in")
	}
	if _, err := client.AuthToken(srv.tokenCodeForSessionForTest(client.SessionID)); err != nil {
		t.Fatalf("correct token code rejected: %v", err)
	}
	if !client.IsLoggedIn() {
		t.Fatal("client not logged in after the correct token code")
	}

	// 6. The completed full-chain session loads the portal resources.
	integration, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}
	if integration.User.Name != "admin" {
		t.Fatalf("integration user = %q, want admin", integration.User.Name)
	}
	if len(integration.ResourceList.TCPUDPResources) == 0 {
		t.Fatal("full-chain session received no resources")
	}
}

// isVerifyCodeChallenge asserts the protocol error kind for the captcha
// challenge (0x66600011 / 0x80 / 0x80000021 all classify as AuthKindVerifyCode).
func isVerifyCodeChallenge(t *testing.T, err error) bool {
	t.Helper()
	var authErr *protocol.AuthError
	return errors.As(err, &authErr) && authErr.Kind == protocol.AuthKindVerifyCode
}
