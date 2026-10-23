package service

// 动态令牌（OTP）链的服务层测试：固定表单的口令登录收到 code 4 挑战后，
// LoginWithToken 在同一挑战会话上提交令牌码完成登录。令牌码错误不消费
// 挑战，可原地重试——与短信链同一套保留机制。

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// newTokenGateway starts a TLS server for the token chain: the password step
// answers code 4 (token factor required, with a session cookie); the token
// step accepts "123456" and answers success, anything else draws 0x109.
func newTokenGateway(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "token-chain-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="4" msg="need token"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("VSG_SESSIONID"); err != nil || c.Value != "token-chain-session" {
			http.Error(w, "session mismatch", http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) == "token=123456" {
			_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
			return
		}
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x109" msg="动态令牌码错误"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<INTERGRATION_INFO><USER name="alice"/><SESSION detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`)
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// TestLoginWithTokenAnswersPasswordChallenge drives the gateway-driven chain
// the fixed login form produces: the password-only login draws the token
// challenge (code 4), the challenge stays on the session, and LoginWithToken
// submits the code over that same session. A wrong code keeps the challenge
// alive; the completed login is recorded as a plain password login.
func TestLoginWithTokenAnswersPasswordChallenge(t *testing.T) {
	server := newTokenGateway(t)
	host, port := hostPortOf(t, server.URL)

	t.Chdir(t.TempDir())
	s := &VPNService{
		Config: &config.AppConfig{Gateways: []config.GatewayProfile{{
			ID:   "gw-0",
			Name: "gw",
			IP:   host,
			Port: port,
		}}},
		CertStore: mustStore(t),
		Status:    "Disconnected",
	}
	defer s.Logout()

	// 1. The password is accepted; the gateway asks for the token factor.
	if _, err := s.Login("gw", "alice", "secret", "", false, false); AuthErrorCode(err) != "token_challenge" {
		t.Fatalf("expected token_challenge, got %v", err)
	}

	// 2. A wrong code is rejected but the challenge stays live for a retry.
	if _, err := s.LoginWithToken("gw", "000000"); AuthErrorCode(err) != "token_code_error" {
		t.Fatalf("expected token_code_error, got %v", err)
	}

	// 3. The right code completes the login on the challenged session.
	res, err := s.LoginWithToken("gw", "123456")
	if err != nil {
		t.Fatalf("LoginWithToken: %v", err)
	}
	if res["authType"] != authTypePassword {
		t.Fatalf("authType = %v, want %q", res["authType"], authTypePassword)
	}
	if s.Status != "Connected" {
		t.Fatalf("status = %q, want Connected", s.Status)
	}

	// 4. The challenge is consumed; a second submission must not succeed.
	if _, err := s.LoginWithToken("gw", "123456"); err == nil {
		t.Fatal("a consumed challenge accepted a second submission")
	}
}

// TestLoginWithTokenRequiresPendingChallenge pins the guard: without a live
// token challenge there is nothing to continue.
func TestLoginWithTokenRequiresPendingChallenge(t *testing.T) {
	server := newTokenGateway(t)
	host, port := hostPortOf(t, server.URL)

	t.Chdir(t.TempDir())
	s := &VPNService{
		Config: &config.AppConfig{Gateways: []config.GatewayProfile{{
			ID:   "gw-0",
			Name: "gw",
			IP:   host,
			Port: port,
		}}},
		CertStore: mustStore(t),
		Status:    "Disconnected",
	}
	if _, err := s.LoginWithToken("gw", "123456"); err == nil {
		t.Fatal("LoginWithToken without a challenge should fail")
	}
}

// TestAuthErrorCodeTokenKinds pins the stable codes the frontend dispatches on.
func TestAuthErrorCodeTokenKinds(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&protocol.AuthError{Kind: protocol.AuthKindTokenRequired, Code: "4"}, "token_challenge"},
		{&protocol.AuthError{Kind: protocol.AuthKindTokenCodeError, Code: "0x109"}, "token_code_error"},
	}
	for _, tc := range cases {
		if got := AuthErrorCode(tc.err); got != tc.want {
			t.Errorf("AuthErrorCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
