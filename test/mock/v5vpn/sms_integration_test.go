package mockserver

// 短信认证链的协议对撞测试：驱动 internal/protocol 客户端连本 mock 的
// sms 模式，验证完整的两步串行流程——
//   - Client.AuthPassword（口令 -> code 8 挑战，msg 与真实网关一致）
//   - Client.SendSMC（GET /vpn/user/auth/send_smc 触发下发）
//   - Client.AuthSMC（错码 -> 0x10A；正确码 -> code 0 建立会话）
//   - Client.FetchIntegration（短信认证会话拉取内网资源）
//
// mock 按真实网关行为校验验证码（绑定挑战会话、错码不重发），所以这条
// 测试同时钉住客户端"在同一会话上提交"的行为：换一个客户端实例提交
// 必然失败。

import (
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func TestMockServerSMSChallengeFlow(t *testing.T) {
	srv, host, port := startTestGateway(t, ModeSMS)

	client := protocol.NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("["+level+"] "+format, args...)
	})

	if _, err := client.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// 1. The password is accepted; the gateway answers the SMS challenge.
	resp, err := client.AuthPassword("admin", "admin123", "")
	if err == nil {
		t.Fatal("expected the SMS challenge, got success")
	}
	if !protocol.IsSMSChallenge(err) {
		t.Fatalf("expected an SMS challenge error, got %v", err)
	}
	if resp == nil || resp.Result.Code != "8" {
		t.Fatalf("expected RESULT code 8, got %+v", resp)
	}
	if resp.Result.Msg != "多因素认证，短信认证" {
		t.Fatalf("challenge msg = %q, want the real gateway's text", resp.Result.Msg)
	}
	if client.SessionID == "" {
		t.Fatal("challenge response did not yield a session the code must bind to")
	}

	// 2. A code submitted before the delivery request has nothing to match.
	if _, err := client.AuthSMC("123456"); !protocol.IsSMCCodeError(err) {
		t.Fatalf("expected 0x10A for an unsent code, got %v", err)
	}

	// 3. The delivery request issues the code on this exact session.
	if err := client.SendSMC(); err != nil {
		t.Fatalf("SendSMC failed: %v", err)
	}

	// 4. A fresh client on the same gateway has no code: the mock must not
	// accept a code that was issued to another session.
	other := protocol.NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("[other:"+level+"] "+format, args...)
	})
	if err := other.SendSMC(); err != nil {
		t.Fatalf("other client SendSMC failed: %v", err)
	}
	if _, err := client.AuthSMC(srv.currentSMSCodeForTest()); !protocol.IsSMCCodeError(err) {
		t.Fatalf("a code reissued to another session must not validate here, got %v", err)
	}

	// 5. The wrong code drawn before the reissue is stale too; request a fresh
	// delivery and submit the code bound to this session.
	if err := client.SendSMC(); err != nil {
		t.Fatalf("SendSMC retry failed: %v", err)
	}
	if _, err := client.AuthSMC("000000"); !protocol.IsSMCCodeError(err) {
		t.Fatalf("expected 0x10A for a wrong code, got %v", err)
	}
	if _, err := client.AuthSMC(srv.currentSMSCodeForTest()); err != nil {
		t.Fatalf("correct SMS code rejected: %v", err)
	}
	if !client.IsLoggedIn() {
		t.Fatal("client not logged in after the correct SMS code")
	}

	// 6. The completed session loads the portal resources.
	integration, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}
	if integration.User.Name != "admin" {
		t.Fatalf("integration user = %q, want admin", integration.User.Name)
	}
	if len(integration.ResourceList.TCPUDPResources) == 0 {
		t.Fatal("SMS-authenticated session received no resources")
	}
}

// currentSMSCodeForTest exposes the last issued code to the test itself. The
// E2E driver reads it over /api/smscode; in-process tests can use this.
func (s *Server) currentSMSCodeForTest() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentSMSCode
}

// TestMockServerPwdCertSMSChain drives the three-factor chain the gateway
// state machine can ask for: password (code 2) -> certificate (code 8) -> SMS
// (code 0). The client side is the exact path the service layer uses
// (AuthPasswordWithCert keeps the certificate factor across the SMS
// challenge), so this test pins the whole chain against gateway-driven
// dispatch rather than a hardcoded flow.
func TestMockServerPwdCertSMSChain(t *testing.T) {
	srv, host, port := startTestGateway(t, ModePwdCertSMS)

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

	// 1. Password -> certificate -> SMS: the two-step call surfaces the SMS
	// challenge with the certificate factor reported as presented.
	resp, err := client.AuthPasswordWithCert(&clientCert, "admin", "admin123", "")
	if !protocol.IsSMSChallenge(err) {
		t.Fatalf("expected the SMS challenge after the certificate factor, got %v", err)
	}
	if resp == nil || !resp.CertFactorUsed {
		t.Fatalf("certificate factor not reported on the challenged chain: %+v", resp)
	}
	if client.SessionID == "" {
		t.Fatal("challenge response did not yield a session the code must bind to")
	}

	// 2. Deliver, fail once (0x10A keeps the challenge), then complete.
	if err := client.SendSMC(); err != nil {
		t.Fatalf("SendSMC failed: %v", err)
	}
	if _, err := client.AuthSMC("000000"); !protocol.IsSMCCodeError(err) {
		t.Fatalf("expected 0x10A for a wrong code, got %v", err)
	}
	if client.IsLoggedIn() {
		t.Fatal("a wrong code must not log the session in")
	}
	if _, err := client.AuthSMC(srv.currentSMSCodeForTest()); err != nil {
		t.Fatalf("correct SMS code rejected: %v", err)
	}
	if !client.IsLoggedIn() {
		t.Fatal("client not logged in after the correct SMS code")
	}

	// 3. The completed three-factor session loads the portal resources.
	integration, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}
	if integration.User.Name != "admin" {
		t.Fatalf("integration user = %q, want admin", integration.User.Name)
	}
	if len(integration.ResourceList.TCPUDPResources) == 0 {
		t.Fatal("three-factor session received no resources")
	}
}

// TestMockServerCertOnlySMSChain drives the other dynamic order the gateway
// may ask for: a standalone certificate login whose cert step draws the SMS
// challenge (certificate -> SMS), completed on the same session.
func TestMockServerCertOnlySMSChain(t *testing.T) {
	srv, host, port := startTestGateway(t, ModePwdCertSMS)

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

	// 1. The certificate factor alone is not enough: the gateway answers the
	// SMS challenge on the cert step.
	if err := client.AuthCertOnly(&clientCert, ""); !protocol.IsSMSChallenge(err) {
		t.Fatalf("expected the SMS challenge on the certificate step, got %v", err)
	}
	if client.IsLoggedIn() {
		t.Fatal("the SMS challenge must not log the session in")
	}
	if client.SessionID == "" {
		t.Fatal("challenge response did not yield a session the code must bind to")
	}

	// 2. The code is delivered and submitted on the challenged session.
	if err := client.SendSMC(); err != nil {
		t.Fatalf("SendSMC failed: %v", err)
	}
	if _, err := client.AuthSMC(srv.currentSMSCodeForTest()); err != nil {
		t.Fatalf("correct SMS code rejected: %v", err)
	}
	if !client.IsLoggedIn() {
		t.Fatal("client not logged in after the correct SMS code")
	}

	integration, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}
	if len(integration.ResourceList.TCPUDPResources) == 0 {
		t.Fatal("certificate + SMS session received no resources")
	}
}
