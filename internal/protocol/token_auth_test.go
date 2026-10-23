package protocol

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The dynamic-token (OTP) factor mirrors the SMS factor's shape: the password
// step is accepted, the gateway answers its challenge bit (0x4), and the code
// from the user's hardware/software token is submitted on
// /vpn/user/auth/token over the same session. The wrong-code rejection 0x109
// is an inference (see AuthKindTokenCodeError); the mock gateway answers it,
// and the real-gateway value is pending capture.

func TestClassifyTokenFactorCodes(t *testing.T) {
	cases := []struct {
		code string
		kind AuthKind
	}{
		{"4", AuthKindTokenRequired},
		{"0x4", AuthKindTokenRequired},
		{"0x109", AuthKindTokenCodeError},
		{"265", AuthKindTokenCodeError},
	}
	for _, tc := range cases {
		if got := classifyAuth(tc.code, ""); got != tc.kind {
			t.Errorf("classify(%s) = %d, want %d", tc.code, got, tc.kind)
		}
	}

	challenge := newAuthError("4", "多因素认证，动态令牌认证")
	if !IsTokenChallenge(challenge) {
		t.Fatal("code 4 not classified as token challenge")
	}
	if IsTokenCodeError(challenge) {
		t.Fatal("challenge misread as wrong-code rejection")
	}
	if !strings.Contains(challenge.Error(), "多因素认证，动态令牌认证") {
		t.Fatalf("challenge error lost the gateway message: %s", challenge.Error())
	}

	mismatch := newAuthError("0x109", "动态令牌码错误")
	if !IsTokenCodeError(mismatch) {
		t.Fatal("0x109 not classified as wrong token code")
	}
	if IsTokenChallenge(mismatch) {
		t.Fatal("wrong-code rejection misread as a fresh challenge")
	}
	if !strings.Contains(mismatch.Error(), "动态令牌码错误") {
		t.Fatalf("mismatch error lost the gateway message: %s", mismatch.Error())
	}

	// SecUI.exe dispatches 0x4 to its Edit_Token state; keep that contract.
	if got := NextAuthStep("4"); got != AuthStepToken {
		t.Fatalf("NextAuthStep(4) = %d, want AuthStepToken", got)
	}
}

func TestTokenAuthBodyMatchesOriginalFormat(t *testing.T) {
	if got := tokenAuthBody("123456"); got != "token=123456" {
		t.Fatalf("tokenAuthBody = %q, want token=123456", got)
	}
}

// TestAuthTokenSubmitsCodeOnTokenEndpoint pins the wire shape of the code
// submission: POST /vpn/user/auth/token with the raw "token=%s" body the
// original client posts (SecLogin.dll format string 0x10041dc8), on the
// session that received the challenge.
func TestAuthTokenSubmitsCodeOnTokenEndpoint(t *testing.T) {
	var gotMethod, gotPath, gotBody, gotContentType string
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/token", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "token-session-1", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)
	resp, err := client.AuthToken("654321")
	if err != nil {
		t.Fatalf("AuthToken failed: %v", err)
	}
	if resp == nil || !isSuccessCode(resp.Result.Code) {
		t.Fatalf("expected success response, got %+v", resp)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/vpn/user/auth/token" {
		t.Errorf("path = %q, want /vpn/user/auth/token", gotPath)
	}
	if gotBody != "token=654321" {
		t.Errorf("body = %q, want token=654321", gotBody)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if client.SessionID != "token-session-1" {
		t.Errorf("session not captured: %q", client.SessionID)
	}
	if !client.IsLoggedIn() {
		t.Error("client not marked logged in after a successful token auth")
	}
}

// TestAuthTokenWrongCodeKeepsChallengeRetryable pins the retry contract over
// the full two-step chain: the password step is accepted with the 0x4
// challenge (and issues the session the code is bound to), a wrong code draws
// 0x109 without killing the session, and the right code then completes the
// login.
func TestAuthTokenWrongCodeKeepsChallengeRetryable(t *testing.T) {
	var attempts int
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "token-challenge-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="4" msg="need token"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/token", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "token=000000") {
			_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x109" msg="动态令牌码错误"/></RESPONSE>`)
			return
		}
		// The session was issued with the challenge; the gateway does not
		// re-send the cookie here.
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)

	// Step 1: the password is accepted and the gateway asks for the token code.
	if _, err := client.AuthPassword("alice", "secret", ""); !IsTokenChallenge(err) {
		t.Fatalf("expected the token challenge, got %v", err)
	}
	if client.SessionID != "token-challenge-session" {
		t.Fatalf("challenge session not captured: %q", client.SessionID)
	}

	// Step 2a: a wrong code is rejected but the challenge stays retryable.
	if _, err := client.AuthToken("000000"); !IsTokenCodeError(err) {
		t.Fatalf("expected wrong-code rejection, got %v", err)
	}
	if client.IsLoggedIn() {
		t.Fatal("a wrong code must not log the session in")
	}

	// Step 2b: the same client retries with the right code and completes.
	if _, err := client.AuthToken("123456"); err != nil {
		t.Fatalf("retry with the right code failed: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("gateway saw %d attempts, want 2", attempts)
	}
	if !client.IsLoggedIn() {
		t.Fatal("client not logged in after the retry")
	}
}
