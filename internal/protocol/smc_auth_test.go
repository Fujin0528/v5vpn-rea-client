package protocol

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The SMS factor mirrors the certificate factor's shape: the password step is
// accepted, the gateway answers its challenge code (0x8), and the code from
// the user's phone is submitted on /vpn/user/auth/smc over the same session.
// These tests pin the classification and the wire behavior against a scripted
// gateway; the full two-step round trip against the mock lives in
// test/mock/v5vpn.

func TestClassifySMSFactorCodes(t *testing.T) {
	cases := []struct {
		code string
		kind AuthKind
	}{
		{"8", AuthKindSMCRequired},
		{"0x8", AuthKindSMCRequired},
		{"0x10A", AuthKindSMCCodeError},
		{"266", AuthKindSMCCodeError},
	}
	for _, tc := range cases {
		if got := classifyAuth(tc.code, ""); got != tc.kind {
			t.Errorf("classify(%s) = %d, want %d", tc.code, got, tc.kind)
		}
	}

	challenge := newAuthError("8", "多因素认证，短信认证")
	if !IsSMSChallenge(challenge) {
		t.Fatal("code 8 not classified as SMS challenge")
	}
	if IsSMCCodeError(challenge) {
		t.Fatal("challenge misread as wrong-code rejection")
	}
	if !strings.Contains(challenge.Error(), "多因素认证，短信认证") {
		t.Fatalf("challenge error lost the gateway message: %s", challenge.Error())
	}

	mismatch := newAuthError("0x10A", "短信码错误")
	if !IsSMCCodeError(mismatch) {
		t.Fatal("0x10A not classified as wrong SMS code")
	}
	if IsSMSChallenge(mismatch) {
		t.Fatal("wrong-code rejection misread as a fresh challenge")
	}
	if !strings.Contains(mismatch.Error(), "短信码错误") {
		t.Fatalf("mismatch error lost the gateway message: %s", mismatch.Error())
	}

	// The portal driver dispatches 0x8 to the SMC step; keep that contract.
	if got := NextAuthStep("8"); got != AuthStepSMC {
		t.Fatalf("NextAuthStep(8) = %d, want AuthStepSMC", got)
	}
}

func TestSMSAuthBodyMatchesOriginalFormat(t *testing.T) {
	if got := smsAuthBody("123456"); got != "smc=123456" {
		t.Fatalf("smsAuthBody = %q, want smc=123456", got)
	}
}

// TestAuthSMCSubmitsCodeOnSMCEndpoint pins the wire shape of the code
// submission: POST /vpn/user/auth/smc with the raw "smc=%s" body the original
// client posts, on the session that received the challenge.
func TestAuthSMCSubmitsCodeOnSMCEndpoint(t *testing.T) {
	var gotMethod, gotPath, gotBody, gotContentType string
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/smc", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "smc-session-1", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)
	resp, err := client.AuthSMC("654321")
	if err != nil {
		t.Fatalf("AuthSMC failed: %v", err)
	}
	if resp == nil || !isSuccessCode(resp.Result.Code) {
		t.Fatalf("expected success response, got %+v", resp)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/vpn/user/auth/smc" {
		t.Errorf("path = %q, want /vpn/user/auth/smc", gotPath)
	}
	if gotBody != "smc=654321" {
		t.Errorf("body = %q, want smc=654321", gotBody)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if client.SessionID != "smc-session-1" {
		t.Errorf("session not captured: %q", client.SessionID)
	}
	if !client.IsLoggedIn() {
		t.Error("client not marked logged in after a successful SMS auth")
	}
}

// TestAuthSMCWrongCodeKeepsChallengeRetryable pins the retry contract over the
// full two-step chain: the password step is accepted with the 0x8 challenge
// (and issues the session the code is bound to), a wrong code draws 0x10A
// without killing the session, and the right code then completes the login.
func TestAuthSMCWrongCodeKeepsChallengeRetryable(t *testing.T) {
	var attempts int
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "smc-challenge-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="8" msg="多因素认证，短信认证"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/smc", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "smc=000000") {
			_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x10A" msg="短信码错误"/></RESPONSE>`)
			return
		}
		// The session was issued with the challenge; the gateway does not
		// re-send the cookie here.
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)

	// Step 1: the password is accepted and the gateway asks for the SMS code.
	if _, err := client.AuthPassword("alice", "secret", ""); !IsSMSChallenge(err) {
		t.Fatalf("expected the SMS challenge, got %v", err)
	}
	if client.SessionID != "smc-challenge-session" {
		t.Fatalf("challenge session not captured: %q", client.SessionID)
	}

	// Step 2a: a wrong code is rejected but the challenge stays retryable.
	if _, err := client.AuthSMC("000000"); !IsSMCCodeError(err) {
		t.Fatalf("expected wrong-code rejection, got %v", err)
	}
	if client.IsLoggedIn() {
		t.Fatal("a wrong code must not log the session in")
	}

	// Step 2b: the same client retries with the right code and completes.
	if _, err := client.AuthSMC("123456"); err != nil {
		t.Fatalf("retry with the right code failed: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("gateway saw %d attempts, want 2", attempts)
	}
	if !client.IsLoggedIn() {
		t.Fatal("client not logged in after the retry")
	}
}

// TestSendSMCRequestsDelivery pins the send-code request: GET
// /vpn/user/auth/send_smc with no body, RESULT code 0 on acceptance, and the
// gateway's rejection surfaced as an auth error.
func TestSendSMCRequestsDelivery(t *testing.T) {
	var gotMethod, gotPath string
	var gotBodyLen int
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/send_smc", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBodyLen = len(b)
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)
	if err := client.SendSMC(); err != nil {
		t.Fatalf("SendSMC failed: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotPath != "/vpn/user/auth/send_smc" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBodyLen != 0 {
		t.Errorf("send_smc carried a body of %d bytes, want none", gotBodyLen)
	}
}

func TestSendSMCSurfacesGatewayRejection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/send_smc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x80000029" msg="短信认证用户没有设置手机号码"/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)
	err := client.SendSMC()
	if err == nil {
		t.Fatal("expected the no-phone rejection to surface")
	}
	if !strings.Contains(err.Error(), "短信认证用户没有设置手机号码") {
		t.Fatalf("rejection lost the gateway message: %v", err)
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("rejection is not an AuthError: %T", err)
	}
}
