package mockserver

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMockServerLifecycleAndAuth(t *testing.T) {
	srv, err := New(Config{
		Addr:        "127.0.0.1:0", // random port
		Mode:        ModePwdCert,
		RequireCert: false,
		Verbose:     false,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Use an http.Server listener
	l, err := tls.Listen("tcp", "127.0.0.1:0", srv.httpSrv.TLSConfig)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	go srv.httpSrv.Serve(l)
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := "https://" + l.Addr().String()

	// 1. Test version.xml
	resp, err := client.Get(baseURL + "/vpn/version.xml")
	if err != nil {
		t.Fatalf("GET /vpn/version.xml failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "VERSION") {
		t.Errorf("Unexpected version body: %s", string(body))
	}

	// 2. Test password auth (pwd-cert mode)
	form := url.Values{
		"username": {"admin"},
		"password": {"admin123"},
		"encode":   {"0"},
	}
	resp, err = client.Post(baseURL+"/vpn/user/auth/password", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /vpn/user/auth/password failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// Should return code="2"
	if !strings.Contains(string(body), `code="2"`) {
		t.Errorf("Expected code=2 in response, got: %s", string(body))
	}

	// Check cookie
	cookies := resp.Cookies()
	var vsgCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "VSG_SESSIONID" {
			vsgCookie = c
			break
		}
	}
	if vsgCookie == nil {
		t.Fatalf("Expected VSG_SESSIONID cookie from password auth")
	}

	// 3. Test cert auth with session cookie
	req, err := http.NewRequest(http.MethodGet, baseURL+"/vpn/user/auth/cert", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.AddCookie(vsgCookie)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /vpn/user/auth/cert failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if !strings.Contains(string(body), `code="0"`) {
		t.Errorf("Expected code=0 from cert auth, got: %s", string(body))
	}

	// 4. Test portal integration
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/vpn/user/portal/intergration.xml", nil)
	req.AddCookie(vsgCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /vpn/user/portal/intergration.xml failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if !strings.Contains(string(body), `SESSION`) {
		t.Errorf("Expected SESSION in integration body: %s", string(body))
	}
}
