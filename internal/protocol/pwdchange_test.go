package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPasswordChangeBodyEncoded(t *testing.T) {
	body := passwordChangeBodyEncoded("旧密码!", "New#Pass")
	want := "old_pwd=" + base64AuthParam("旧密码!") +
		"&new_pwd=" + base64AuthParam("New#Pass") + "&encode=1"
	if body != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	if !strings.Contains(body, "encode=1") {
		t.Fatalf("body missing encode=1: %q", body)
	}
	// Base64 形态下旧口令不应以明文出现。
	if strings.Contains(body, "旧密码!") {
		t.Fatalf("plaintext old password leaked into body: %q", body)
	}
}

func TestIsPasswordMismatch(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"bad-credentials kind", &AuthError{Kind: AuthKindBadCredentials, Code: "0x101", Msg: "拒绝"}, true},
		{"msg 原密码", &AuthError{Kind: AuthKindOther, Msg: "原密码错误"}, true},
		{"msg 旧密码", &AuthError{Kind: AuthKindOther, Msg: "旧密码不正确"}, true},
		{"msg 密码错误", &AuthError{Kind: AuthKindOther, Msg: "新密码不符合策略密码错误次数过多"}, true},
		{"msg 其他", &AuthError{Kind: AuthKindOther, Msg: "新密码强度不足"}, false},
		{"verify-code kind", &AuthError{Kind: AuthKindVerifyCode, Msg: "验证码错误"}, false},
		{"plain error", errors.New("network timeout"), false},
		{"wrapped auth error", fmt.Errorf("wrap: %w", &AuthError{Kind: AuthKindBadCredentials}), true},
	}
	for _, tc := range cases {
		if got := isPasswordMismatch(tc.err); got != tc.want {
			t.Errorf("%s: isPasswordMismatch = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestChangePasswordRetriesWithBase64Encoding 覆盖双编码改密回退：
// 网关先按明文口径把 old_pwd 判错，客户端换 Base64 + encode=1 重试成功。
func TestChangePasswordRetriesWithBase64Encoding(t *testing.T) {
	var mu sync.Mutex
	var bodies []string

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.TrimSpace(readAll(t, r))
		mu.Lock()
		bodies = append(bodies, body)
		n := len(bodies)
		mu.Unlock()

		w.Header().Set("Content-Type", "text/xml")
		if n == 1 {
			// 第一跳：明文被网关按 Base64 解码，判「原密码错误」。
			_, _ = w.Write([]byte(`<RESPONSE><RESULT code="0x101" msg="原密码错误"/></RESPONSE>`))
			return
		}
		_, _ = w.Write([]byte(`<RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`))
	}))
	defer srv.Close()

	client := testClient(t, srv)

	if err := client.ChangePassword("user", "OldPass123", "NewPass456", ""); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if len(bodies) != 2 {
		t.Fatalf("gateway received %d pwdchange requests, want 2 (plaintext then base64)", len(bodies))
	}
	first, second := bodies[0], bodies[1]

	if want := "old_pwd=OldPass123"; !strings.Contains(first, want) {
		t.Errorf("first body %q missing plaintext form %q", first, want)
	}
	if want := "new_pwd=NewPass456"; !strings.Contains(first, want) {
		t.Errorf("first body %q missing plaintext form %q", first, want)
	}
	if !strings.Contains(second, "encode=1") {
		t.Errorf("second body %q missing encode=1", second)
	}
	if want := "old_pwd=" + base64.StdEncoding.EncodeToString([]byte("OldPass123")); !strings.Contains(second, want) {
		t.Errorf("second body %q missing base64 old_pwd %q", second, want)
	}
	if strings.Contains(second, "OldPass123") {
		t.Errorf("second body %q still carries plaintext old password", second)
	}
}

// TestChangePasswordPlaintextRejectedTwice 覆盖不回退的场景：两次都判错时
// 必须把错误返回给上层，而不是无限重试或吞掉。
func TestChangePasswordPlaintextRejectedTwice(t *testing.T) {
	var count int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = readAll(t, r)
		count++
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<RESPONSE><RESULT code="0x101" msg="原密码错误"/></RESPONSE>`))
	}))
	defer srv.Close()

	client := testClient(t, srv)

	err := client.ChangePassword("user", "WrongOld", "NewPass456", "")
	if err == nil {
		t.Fatal("ChangePassword unexpectedly succeeded with a wrong old password")
	}
	if !isPasswordMismatch(err) {
		t.Fatalf("error should classify as password mismatch, got %v", err)
	}
	if count != 2 {
		t.Fatalf("gateway received %d requests, want exactly 2 (no third retry)", count)
	}
}

func readAll(t *testing.T, r *http.Request) string {
	t.Helper()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	return string(data)
}
