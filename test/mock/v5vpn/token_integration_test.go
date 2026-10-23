package mockserver

// 动态令牌（OTP）链的协议对撞测试：驱动 internal/protocol 客户端连本
// mock 的 token 模式，验证完整的两步串行流程——
//   - Client.AuthPassword（口令 -> code 4 挑战，同时 mock 生成绑定会话
//     的令牌码，即「用户令牌当前显示」）
//   - Client.AuthToken（错码 -> 0x109 挑战保留；正确码 -> code 0 建立会话）
//   - Client.FetchIntegration（令牌认证会话拉取内网资源）
//
// 与短信链不同，令牌没有「发送」步骤：码由用户手中的硬件/软件令牌自行
// 生成，mock 在挑战下发时生成并经 /api/tokencode 暴露给测试。0x109 是
// 推断值（真实网关的令牌码错误结果码尚未取证），mock 与客户端按同一
// 常量对撞。

import (
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func TestMockServerPwdTokenChain(t *testing.T) {
	srv, host, port := startTestGateway(t, ModeToken)

	client := protocol.NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("["+level+"] "+format, args...)
	})

	if _, err := client.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// 1. The password is accepted; the gateway answers the token challenge.
	resp, err := client.AuthPassword("admin", "admin123", "")
	if err == nil {
		t.Fatal("expected the token challenge, got success")
	}
	if !protocol.IsTokenChallenge(err) {
		t.Fatalf("expected a token challenge error, got %v", err)
	}
	if resp == nil || resp.Result.Code != "4" {
		t.Fatalf("expected RESULT code 4, got %+v", resp)
	}
	if client.SessionID == "" {
		t.Fatal("challenge response did not yield a session the code must bind to")
	}

	// 2. A wrong code is rejected with 0x109 and the challenge stays live.
	if _, err := client.AuthToken("000000"); !protocol.IsTokenCodeError(err) {
		t.Fatalf("expected 0x109 for a wrong code, got %v", err)
	}
	if client.IsLoggedIn() {
		t.Fatal("a wrong code must not log the session in")
	}

	// 3. A fresh client has its own challenge and its own token code: the
	// code issued to the first session must not validate on another session.
	other := protocol.NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("[other:"+level+"] "+format, args...)
	})
	if _, err := other.AuthPassword("admin", "admin123", ""); !protocol.IsTokenChallenge(err) {
		t.Fatalf("other client expected the token challenge, got %v", err)
	}
	// currentTokenCode now mirrors the OTHER session's token display.
	if _, err := client.AuthToken(srv.currentTokenCodeForTest()); !protocol.IsTokenCodeError(err) {
		t.Fatal("a code reissued to another session must not validate here")
	}

	// 4. The code bound to this session completes the login.
	if _, err := client.AuthToken(srv.tokenCodeForSessionForTest(client.SessionID)); err != nil {
		t.Fatalf("correct token code rejected: %v", err)
	}
	if !client.IsLoggedIn() {
		t.Fatal("client not logged in after the correct token code")
	}

	// 5. The completed session loads the portal resources.
	integration, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}
	if integration.User.Name != "admin" {
		t.Fatalf("integration user = %q, want admin", integration.User.Name)
	}
	if len(integration.ResourceList.TCPUDPResources) == 0 {
		t.Fatal("token-authenticated session received no resources")
	}
}

// currentTokenCodeForTest exposes the last issued token code to the test
// itself. The E2E driver reads it over /api/tokencode; in-process tests can
// use this.
func (s *Server) currentTokenCodeForTest() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentTokenCode
}

// tokenCodeForSessionForTest returns the token code bound to one session, so
// a test can submit the code "its own token displays" even after another
// session's challenge overwrote the global mirror.
func (s *Server) tokenCodeForSessionForTest(sessionID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sess, ok := s.sessions[sessionID]; ok && sess != nil {
		return sess.TokenCode
	}
	return ""
}
