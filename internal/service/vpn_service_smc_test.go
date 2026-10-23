package service

// 短信认证挑战的服务层测试：Login 收到 code 8 后保留挑战会话，
// SendSMSCode / LoginWithSMSCode 都必须复用那个会话（网关把短信码绑定在
// 挑战响应下发的 VSG_SESSIONID 上），错码可重试，正确码进入已连接状态。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
)

// newTestClientCert builds a throwaway self-signed client certificate for the
// certificate-factor chain tests.
func newTestClientCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smc-chain-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func newSMCGateway(t *testing.T) (*httptest.Server, *smcGatewayState) {
	t.Helper()
	st := &smcGatewayState{}
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		st.record("password")
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "sms-challenge-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="8" msg="多因素认证，短信认证"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/send_smc", func(w http.ResponseWriter, r *http.Request) {
		st.recordCookie("send_smc", r.Header.Get("Cookie"))
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/smc", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		st.recordCookie("smc", r.Header.Get("Cookie"))
		if strings.Contains(string(body), "smc=123456") {
			_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
			return
		}
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x10A" msg="短信码错误"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<INTERGRATION_INFO><USER name="alice"/><SESSION detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`)
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, st
}

type smcGatewayState struct {
	mu      sync.Mutex
	calls   map[string]int
	cookies map[string]string
}

func (st *smcGatewayState) record(endpoint string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.calls == nil {
		st.calls = map[string]int{}
	}
	st.calls[endpoint]++
}

func (st *smcGatewayState) recordCookie(endpoint, cookie string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.calls == nil {
		st.calls = map[string]int{}
	}
	st.calls[endpoint]++
	if st.cookies == nil {
		st.cookies = map[string]string{}
	}
	st.cookies[endpoint] = cookie
}

func (st *smcGatewayState) callCount(endpoint string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.calls[endpoint]
}

func (st *smcGatewayState) cookieOf(endpoint string) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.cookies[endpoint]
}

func newSMCService(t *testing.T, srv *httptest.Server) *VPNService {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	s := NewVPNService(nil)
	s.Config = &config.AppConfig{
		Gateways: []config.GatewayProfile{{
			ID:   "gw-test",
			Name: "gw-test",
			IP:   host,
			Port: port,
		}},
	}
	t.Cleanup(func() { _, _ = s.Logout() })
	return s
}

func TestSMSChallengeFlowCompletesLogin(t *testing.T) {
	srv, st := newSMCGateway(t)
	s := newSMCService(t, srv)

	// 1. The password is accepted; the gateway asks for the SMS factor.
	_, err := s.Login("gw-test", "alice", "secret", "", false, false)
	if err == nil {
		t.Fatal("expected the SMS challenge")
	}
	if got := AuthErrorCode(err); got != "sms_challenge" {
		t.Fatalf("AuthErrorCode = %q, want sms_challenge (err: %v)", got, err)
	}

	// 2. Sending the code and submitting it must reuse the challenged client:
	// the gateway bound the code to the session of the code-8 response.
	if err := s.SendSMSCode("gw-test"); err != nil {
		t.Fatalf("SendSMSCode failed: %v", err)
	}
	if got := st.cookieOf("send_smc"); !strings.Contains(got, "VSG_SESSIONID=sms-challenge-session") {
		t.Fatalf("send_smc did not carry the challenge session: %q", got)
	}

	// 3. A wrong code is rejected but keeps the challenge retryable.
	if _, err := s.LoginWithSMSCode("gw-test", "000000"); AuthErrorCode(err) != "sms_code_error" {
		t.Fatalf("expected sms_code_error, got %v", err)
	}
	if st.callCount("password") != 1 {
		t.Fatalf("a wrong code must not restart the password step (password calls: %d)", st.callCount("password"))
	}

	// 4. The right code completes the login on the same session.
	res, err := s.LoginWithSMSCode("gw-test", "123456")
	if err != nil {
		t.Fatalf("LoginWithSMSCode failed: %v", err)
	}
	if res["status"] != "Connected" {
		t.Fatalf("expected Connected, got %v", res["status"])
	}
	if res["authType"] != authTypePassword {
		t.Fatalf("authType = %v, want %q", res["authType"], authTypePassword)
	}
	if got := st.cookieOf("smc"); !strings.Contains(got, "VSG_SESSIONID=sms-challenge-session") {
		t.Fatalf("smc did not carry the challenge session: %q", got)
	}
	if st.callCount("password") != 1 {
		t.Fatalf("the SMS step must reuse the challenged client (password calls: %d)", st.callCount("password"))
	}

	// 5. The challenge is consumed: another submission must not succeed.
	if _, err := s.LoginWithSMSCode("gw-test", "123456"); err == nil {
		t.Fatal("a consumed challenge accepted a second submission")
	}
}

func TestSMSChallengeRequiresPendingChallenge(t *testing.T) {
	srv, _ := newSMCGateway(t)
	s := newSMCService(t, srv)

	if err := s.SendSMSCode("gw-test"); err == nil {
		t.Fatal("SendSMSCode without a challenge should fail")
	}
	if _, err := s.LoginWithSMSCode("gw-test", "123456"); err == nil {
		t.Fatal("LoginWithSMSCode without a challenge should fail")
	}
}

func TestFreshLoginSupersedesSMSChallenge(t *testing.T) {
	srv, st := newSMCGateway(t)
	s := newSMCService(t, srv)

	if _, err := s.Login("gw-test", "alice", "secret", "", false, false); AuthErrorCode(err) != "sms_challenge" {
		t.Fatalf("expected the SMS challenge, got %v", err)
	}

	// A logout drops the challenge with the session.
	if _, err := s.Logout(); err != nil {
		t.Fatal(err)
	}
	if err := s.SendSMSCode("gw-test"); err == nil {
		t.Fatal("SendSMSCode after logout should fail")
	}

	// And a fresh login attempt starts a new challenge rather than reviving
	// the old one.
	if _, err := s.Login("gw-test", "alice", "secret", "", false, false); AuthErrorCode(err) != "sms_challenge" {
		t.Fatalf("expected a fresh SMS challenge, got %v", err)
	}
	if st.callCount("password") != 2 {
		t.Fatalf("password calls = %d, want 2", st.callCount("password"))
	}
}

// TestSMSChallengeAfterCertFactorKeepsCertificate covers the
// password -> certificate -> SMS chain: the certificate factor was presented
// before the SMS challenge, so the completed login is recorded (and tunneled)
// as password + certificate.
func TestSMSChallengeAfterCertFactorKeepsCertificate(t *testing.T) {
	var (
		mu          sync.Mutex
		certCalls   int
		persistedGW string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "chain-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="2" msg="need cert"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/cert", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		certCalls++
		mu.Unlock()
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="8" msg="多因素认证，短信认证"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/send_smc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/smc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<INTERGRATION_INFO><USER name="alice"/><SESSION detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	s := newSMCService(t, srv)
	cert := newTestClientCert(t)

	afterAuth := func(gwID string) {
		mu.Lock()
		persistedGW = gwID
		mu.Unlock()
	}

	// The two-factor login presents the certificate and then hits the SMS
	// challenge.
	_, err := s.loginWithPasswordCert("gw-test", "alice", "secret", "", cert, afterAuth, false, false)
	if AuthErrorCode(err) != "sms_challenge" {
		t.Fatalf("expected the SMS challenge after the cert factor, got %v", err)
	}
	mu.Lock()
	calls := certCalls
	mu.Unlock()
	if calls != 1 {
		t.Fatalf("certificate step calls = %d, want 1", calls)
	}

	if err := s.SendSMSCode("gw-test"); err != nil {
		t.Fatalf("SendSMSCode failed: %v", err)
	}
	res, err := s.LoginWithSMSCode("gw-test", "123456")
	if err != nil {
		t.Fatalf("LoginWithSMSCode failed: %v", err)
	}
	if res["authType"] != authTypePasswordCertificate {
		t.Fatalf("authType = %v, want %q", res["authType"], authTypePasswordCertificate)
	}
	mu.Lock()
	gotPersisted := persistedGW
	mu.Unlock()
	if gotPersisted != "gw-test" {
		t.Fatalf("certificate selection not persisted after the SMS step (got %q)", gotPersisted)
	}
}

// TestSMSChallengeAfterCertOnlyLoginKeepsCertificate covers the
// certificate -> SMS chain: a certificate login whose cert step draws the
// SMS challenge keeps the certificate installed on the challenged client, so
// the code submission still presents it over mutual TLS, and the completed
// login is recorded (and persisted) as a certificate session.
func TestSMSChallengeAfterCertOnlyLoginKeepsCertificate(t *testing.T) {
	var (
		mu        sync.Mutex
		smcPeerCN string
		persisted string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/auth/cert", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "cert-sms-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="8" msg="多因素认证，短信认证"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/send_smc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/smc", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			smcPeerCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		mu.Unlock()
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<INTERGRATION_INFO><USER name="alice"/><SESSION detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`)
	})

	// Request (not require) a client certificate so the handler can assert the
	// challenged client still presents the certificate on the SMS submission.
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	defer srv.Close()
	s := newSMCService(t, srv)
	cert := newTestClientCert(t)

	afterAuth := func(gwID string) {
		mu.Lock()
		persisted = gwID
		mu.Unlock()
	}

	if _, err := s.loginWithLoadedCert("gw-test", cert, "", afterAuth); AuthErrorCode(err) != "sms_challenge" {
		t.Fatalf("expected the SMS challenge after the certificate step, got %v", err)
	}

	if err := s.SendSMSCode("gw-test"); err != nil {
		t.Fatalf("SendSMSCode failed: %v", err)
	}
	res, err := s.LoginWithSMSCode("gw-test", "123456")
	if err != nil {
		t.Fatalf("LoginWithSMSCode failed: %v", err)
	}
	if res["authType"] != authTypeCertificate {
		t.Fatalf("authType = %v, want %q", res["authType"], authTypeCertificate)
	}
	mu.Lock()
	gotCN, gotPersisted := smcPeerCN, persisted
	mu.Unlock()
	if gotCN != "smc-chain-cert" {
		t.Fatalf("the SMS submission did not present the client certificate (peer CN: %q)", gotCN)
	}
	if gotPersisted != "gw-test" {
		t.Fatalf("certificate selection not persisted after the SMS step (got %q)", gotPersisted)
	}
}

// TestSMSChallengeWithoutCertFactorCompletesAsPassword covers the other
// branch: the gateway asks for the SMS factor directly on the password step,
// so even a login started from the password + certificate tab must complete
// as a plain password session — the certificate was never presented and must
// not be recorded as a used factor.
func TestSMSChallengeWithoutCertFactorCompletesAsPassword(t *testing.T) {
	var certCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "pwd-sms-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="8" msg="多因素认证，短信认证"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/cert", func(w http.ResponseWriter, r *http.Request) {
		certCalls++
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/send_smc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/smc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<INTERGRATION_INFO><USER name="alice"/><SESSION detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	s := newSMCService(t, srv)
	cert := newTestClientCert(t)

	persisted := false
	afterAuth := func(gwID string) { persisted = true }

	if _, err := s.loginWithPasswordCert("gw-test", "alice", "secret", "", cert, afterAuth, false, false); AuthErrorCode(err) != "sms_challenge" {
		t.Fatalf("expected the SMS challenge, got %v", err)
	}
	if certCalls != 0 {
		t.Fatalf("certificate step ran %d times, want 0 (gateway asked for SMS only)", certCalls)
	}

	if err := s.SendSMSCode("gw-test"); err != nil {
		t.Fatalf("SendSMSCode failed: %v", err)
	}
	res, err := s.LoginWithSMSCode("gw-test", "123456")
	if err != nil {
		t.Fatalf("LoginWithSMSCode failed: %v", err)
	}
	if res["authType"] != authTypePassword {
		t.Fatalf("authType = %v, want %q", res["authType"], authTypePassword)
	}
	if persisted {
		t.Fatal("certificate selection persisted although the certificate factor was never requested")
	}
}
