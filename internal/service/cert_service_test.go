package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/hygkui/v5vpn-rea-client/internal/certstore"
	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// hostPortOf splits an httptest server URL into the host and port a gateway
// profile needs.
func hostPortOf(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("bad port in %q: %v", rawURL, err)
	}
	return host, port
}

func TestAuthErrorCodeCertificateKinds(t *testing.T) {
	cases := []struct {
		kind protocol.AuthKind
		want string
	}{
		{protocol.AuthKindCertInvalid, "cert_invalid"},
		{protocol.AuthKindCertUnavailable, "cert_unavailable"},
		{protocol.AuthKindCertExpired, "cert_expired"},
		{protocol.AuthKindCertRevoked, "cert_revoked"},
		{protocol.AuthKindCertBadSignature, "cert_signature"},
	}
	for _, tc := range cases {
		err := &protocol.AuthError{Kind: tc.kind, Code: "0x103"}
		if got := AuthErrorCode(err); got != tc.want {
			t.Fatalf("kind %v: got %q want %q", tc.kind, got, tc.want)
		}
		if IsPasswordExpired(err) {
			t.Fatalf("certificate error must not look like a password challenge: %v", tc.kind)
		}
	}
}

func TestListCertificatesEmptyStore(t *testing.T) {
	s := &VPNService{
		Config:    &config.AppConfig{},
		CertStore: mustStore(t),
	}
	list, err := s.ListCertificates(int(certstore.SourceFile))
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %+v", list)
	}
}

func TestImportCertificateValidatesPassword(t *testing.T) {
	s := &VPNService{
		Config:    &config.AppConfig{},
		CertStore: mustStore(t),
	}
	if _, err := s.ImportCertificate("", "", ""); err == nil {
		t.Fatal("expected an error for an empty path")
	}
	if _, err := s.ImportCertificate(filepath.Join(t.TempDir(), "missing.p12"), "", ""); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// TestLoginWithCertUnknownCertificate verifies the failure is reported without
// leaving the service in "Connecting".
func TestLoginWithCertUnknownCertificate(t *testing.T) {
	s := &VPNService{
		Config: &config.AppConfig{
			LastUseGateway: "gw",
			Gateways: []config.GatewayProfile{{
				ID:   "gw-0",
				Name: "gw",
				IP:   "203.0.113.10",
				Port: 443,
			}},
		},
		CertStore: mustStore(t),
		Status:    "Disconnected",
	}
	_, err := s.LoginWithCert("gw", int(certstore.SourceFile), "does-not-exist", "", false)
	if err == nil {
		t.Fatal("expected an error for an unknown certificate")
	}
	if !errors.Is(err, certstore.ErrCertNotFound) {
		t.Fatalf("expected ErrCertNotFound, got %v", err)
	}
	if s.Status != "Error" {
		t.Fatalf("expected status Error, got %q", s.Status)
	}
}

func TestLoginWithCertWhileConnectedRejected(t *testing.T) {
	s := &VPNService{
		Config:    &config.AppConfig{},
		CertStore: mustStore(t),
		Status:    "Connected",
	}
	if _, err := s.LoginWithCert("gw", 0, "id", "", false); err == nil {
		t.Fatal("expected an error while connected")
	}
}

func mustStore(t *testing.T) *certstore.Store {
	t.Helper()
	store, err := certstore.NewStore(filepath.Join(t.TempDir(), "certs"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// twoFactorServiceProbe records what the two-step service-flow mock observed.
type twoFactorServiceProbe struct {
	sawCertStep bool
}

// newTwoFactorGateway starts a TLS server for the two-step two-factor flow:
// the password step runs without a client certificate and answers code 2
// ("certificate factor required", with a session cookie), unless authResult
// overrides that; the certificate step must present the client certificate,
// reuses the session cookie and answers success.
func newTwoFactorGateway(t *testing.T, probe *twoFactorServiceProbe, authResult string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			t.Errorf("password step arrived with a client certificate")
		}
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "two-factor-session", Path: "/"})
		if authResult != "" {
			_, _ = io.WriteString(w, `<RESPONSE>`+authResult+`</RESPONSE>`)
			return
		}
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="2" msg="certificate factor required"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/cert", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusBadRequest)
			return
		}
		if probe != nil {
			probe.sawCertStep = true
		}
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "two-factor-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`)
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

// mustImportCert imports a PKCS#12 certificate into a fresh store and returns
// its id.
func mustImportCert(t *testing.T, store *certstore.Store, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pfx, err := pkcs12.Modern.Encode(key, leaf, nil, "secret")
	if err != nil {
		t.Fatalf("encode pkcs12: %v", err)
	}
	path := filepath.Join(t.TempDir(), "client.p12")
	if err := os.WriteFile(path, pfx, 0o600); err != nil {
		t.Fatalf("write p12: %v", err)
	}
	info, err := store.ImportFile(path, cn, "secret")
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	return info.ID
}

// TestLoginWithPasswordAndCert proves the two-step two-factor flow end to
// end: the password goes out without a certificate, the gateway asks for the
// certificate factor, the certificate step presents it over the same session,
// and the gateway profile remembers the double factor.
func TestLoginWithPasswordAndCert(t *testing.T) {
	probe := &twoFactorServiceProbe{}
	server := newTwoFactorGateway(t, probe, "")
	host, port := hostPortOf(t, server.URL)

	t.Chdir(t.TempDir())
	store := mustStore(t)
	certID := mustImportCert(t, store, "two-factor-client")

	s := &VPNService{
		Config: &config.AppConfig{Gateways: []config.GatewayProfile{{
			ID:   "gw-0",
			Name: "gw",
			IP:   host,
			Port: port,
		}}},
		CertStore: store,
		Status:    "Disconnected",
	}
	defer s.Logout()

	res, err := s.LoginWithPasswordAndCert("gw", "alice", "secret", "", 0, certID, true, false)
	if err != nil {
		t.Fatalf("LoginWithPasswordAndCert: %v", err)
	}
	if !probe.sawCertStep {
		t.Fatal("the certificate step did not present the client certificate")
	}
	if res["authType"] != "password+certificate" {
		t.Fatalf("authType = %v, want password+certificate", res["authType"])
	}
	if s.Client == nil || s.Client.ClientCertificate() == nil {
		t.Fatal("session client did not retain the certificate for the tunnel")
	}
	if s.Status != "Connected" {
		t.Fatalf("status = %q, want Connected", s.Status)
	}

	gw := s.GetGateways()[0]
	if !gw.CertWithPassword || gw.SelectedCertID != certID || gw.AuthType != 0 {
		t.Fatalf("two-factor selection was not persisted: %+v", gw)
	}
}

// TestLoginWithPasswordAndCertPasswordOnlyGateway covers a gateway that
// accepts the password alone even though the user picked the two-factor tab.
// The session must be recorded as a plain password login: persisting the
// two-factor flag would force the two-factor tab on the next launch for a
// gateway that never asked for a certificate.
func TestLoginWithPasswordAndCertPasswordOnlyGateway(t *testing.T) {
	server := newTwoFactorGateway(t, nil, `<RESULT code="0" msg="ok"/>`)
	host, port := hostPortOf(t, server.URL)

	t.Chdir(t.TempDir())
	store := mustStore(t)
	certID := mustImportCert(t, store, "two-factor-client")

	s := &VPNService{
		Config: &config.AppConfig{Gateways: []config.GatewayProfile{{
			ID:   "gw-0",
			Name: "gw",
			IP:   host,
			Port: port,
		}}},
		CertStore: store,
		Status:    "Disconnected",
	}
	defer s.Logout()

	res, err := s.LoginWithPasswordAndCert("gw", "alice", "secret", "", 0, certID, false, false)
	if err != nil {
		t.Fatalf("LoginWithPasswordAndCert: %v", err)
	}
	if res["authType"] != "password" {
		t.Fatalf("authType = %v, want password", res["authType"])
	}
	gw := s.GetGateways()[0]
	if gw.CertWithPassword {
		t.Fatalf("a password-only success was recorded as two-factor: %+v", gw)
	}
}

// A rejected two-factor login must not rewrite the stored mode.
func TestLoginWithPasswordAndCertRejectedKeepsSavedMode(t *testing.T) {
	server := newTwoFactorGateway(t, nil, `<RESULT code="0x101" msg="用户名或密码错误"/>`)
	host, port := hostPortOf(t, server.URL)

	t.Chdir(t.TempDir())
	store := mustStore(t)
	certID := mustImportCert(t, store, "two-factor-client")

	s := &VPNService{
		Config: &config.AppConfig{Gateways: []config.GatewayProfile{{
			ID:               "gw-0",
			Name:             "gw",
			IP:               host,
			Port:             port,
			CertWithPassword: true,
			SelectedCertID:   certID,
		}}},
		CertStore: store,
		Status:    "Disconnected",
	}

	if _, err := s.LoginWithPasswordAndCert("gw", "alice", "wrong", "", 0, certID, true, false); err == nil {
		t.Fatal("expected the gateway to reject the password")
	}
	gw := s.GetGateways()[0]
	if !gw.CertWithPassword || gw.SelectedCertID != certID {
		t.Fatalf("a rejected login erased the two-factor setting: %+v", gw)
	}
}

// TestLoginWithPasswordAndCertUnknownCertificate reports a clear error and
// never leaves the service half-connected.
func TestLoginWithPasswordAndCertUnknownCertificate(t *testing.T) {
	s := &VPNService{
		Config: &config.AppConfig{Gateways: []config.GatewayProfile{{
			ID: "gw-0", Name: "gw", IP: "203.0.113.10", Port: 443,
		}}},
		CertStore: mustStore(t),
		Status:    "Disconnected",
	}
	_, err := s.LoginWithPasswordAndCert("gw", "alice", "secret", "", 0, "does-not-exist", false, false)
	if !errors.Is(err, certstore.ErrCertNotFound) {
		t.Fatalf("expected ErrCertNotFound, got %v", err)
	}
	if s.Status != "Error" {
		t.Fatalf("expected status Error, got %q", s.Status)
	}
}

// A plain password login on a gateway that already remembers the two-factor
// mode clears that mode, so the next launch does not require a certificate
// the user deliberately stopped using.
func TestLoginClearsStoredTwoFactorMode(t *testing.T) {
	s := &VPNService{
		Config: &config.AppConfig{Gateways: []config.GatewayProfile{{
			ID:               "gw-0",
			Name:             "gw",
			IP:               "203.0.113.10",
			Port:             443,
			CertWithPassword: true,
			SelectedCertID:   "some-cert",
		}}},
		CertStore: mustStore(t),
		Status:    "Disconnected",
	}
	t.Chdir(t.TempDir())

	s.rememberPasswordMode("gw")
	gw := s.GetGateways()[0]
	if gw.CertWithPassword {
		t.Fatalf("password login left the two-factor flag set: %+v", gw)
	}
	if gw.SelectedCertID != "some-cert" {
		t.Fatalf("the certificate id must survive for a one-click switch back: %+v", gw)
	}
}
