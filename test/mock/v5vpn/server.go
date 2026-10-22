package mockserver

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Mode defines the gateway simulation mode.
type Mode string

const (
	ModePwdCert    Mode = "pwd-cert"   // Two-factor: Password -> code 2 -> Cert -> code 0
	ModePwdOnly    Mode = "pwd-only"   // Single-factor: Password -> code 0
	ModeCertOnly   Mode = "cert-only"  // Standalone mTLS Certificate -> code 0
	ModePwdChange  Mode = "pwd-change" // Password expired: Password -> code 256 -> PwdChange -> code 0
	ModeVerifyCode Mode = "verifycode" // Captcha required: Password -> code 0x80 -> Captcha -> code 0
	ModeToken      Mode = "token"      // Password -> code 4 -> Token -> code 0
	ModeSMS        Mode = "sms"        // Password -> code 8 -> SMS -> code 0
	ModeErrAuth    Mode = "err-auth"   // Invalid credentials -> code 0x8000001a
	ModeErrCert    Mode = "err-cert"   // Expired/Invalid certificate -> code 0x106
)

// Config holds options for the mock server.
type Config struct {
	Addr         string
	Mode         Mode
	ExpectedUser string
	ExpectedPwd  string
	RequireCert  bool
	Verbose      bool
}

// Session tracks an active client session.
type Session struct {
	ID         string
	Username   string
	PassedPwd  bool
	PassedCert bool
	CreatedAt  time.Time
}

// Server simulates a Leadsec / WangYu V5VPN SSL VPN Gateway.
type Server struct {
	cfg      Config
	httpSrv  *http.Server
	certPEM  []byte
	mu       sync.RWMutex
	sessions map[string]*Session
	mode     Mode
}

// New creates a new V5VPN mock server.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8443"
	}
	if cfg.Mode == "" {
		cfg.Mode = ModePwdCert
	}
	if cfg.ExpectedUser == "" {
		cfg.ExpectedUser = "admin"
	}
	if cfg.ExpectedPwd == "" {
		cfg.ExpectedPwd = "admin123"
	}

	tlsCert, certPEM, err := GenerateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	s := &Server{
		cfg:      cfg,
		certPEM:  certPEM,
		sessions: make(map[string]*Session),
		mode:     cfg.Mode,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		// RequestClientCert requests client certificate if presented, without dropping TLS connection if absent
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS10,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", s.handleVersion)
	mux.HandleFunc("/vpn/user/auth/password", s.handlePassword)
	mux.HandleFunc("/vpn/user/auth/cert", s.handleCert)
	mux.HandleFunc("/vpn/user/auth/token", s.handleToken)
	mux.HandleFunc("/vpn/user/auth/smc", s.handleSMS)
	mux.HandleFunc("/vpn/user/auth/pwdchange", s.handlePwdChange)
	mux.HandleFunc("/vpn/user/portal/intergration.xml", s.handleIntegration)
	mux.HandleFunc("/vpn/user/logout", s.handleLogout)
	mux.HandleFunc("/api/mode", s.handleAPIMode)
	mux.HandleFunc("/", s.handleIndex)

	s.httpSrv = &http.Server{
		Addr:      cfg.Addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	return s, nil
}

// Start begins listening and serving HTTPS requests.
func (s *Server) Start() error {
	log.Printf("[MockServer] Gateway listening on https://%s (Mode: %s)", s.cfg.Addr, s.GetMode())
	return s.httpSrv.ListenAndServeTLS("", "")
}

// Close gracefully stops the server.
func (s *Server) Close() error {
	return s.httpSrv.Close()
}

// GetMode returns the current active simulation mode.
func (s *Server) GetMode() Mode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// SetMode dynamically changes the simulation mode.
func (s *Server) SetMode(m Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
	log.Printf("[MockServer] Simulation mode changed to: %s", m)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>V5VPN Gateway Mock Server</title>
<style>
body { font-family: -apple-system, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }
h1 { color: #38bdf8; }
.card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
code { background: #334155; padding: 2px 6px; border-radius: 4px; color: #f1f5f9; }
button { padding: 8px 16px; margin: 4px; border-radius: 4px; border: none; background: #38bdf8; color: #0f172a; font-weight: bold; cursor: pointer; }
button:hover { background: #0284c7; color: #fff; }
</style>
</head>
<body>
<h1>🛡️ Leadsec / 网御星云 V5VPN Gateway Mock Server</h1>
<div class="card">
  <p><strong>Status:</strong> Running</p>
  <p><strong>Current Mode:</strong> <code>%s</code></p>
  <p><strong>Expected User:</strong> <code>%s</code> / <code>%s</code></p>
  <p><strong>Switch Simulation Flow:</strong></p>
  <button onclick="setMode('pwd-cert')">🔐 口令+证书双因素 (pwd-cert)</button>
  <button onclick="setMode('pwd-only')">🔑 仅口令直连 (pwd-only)</button>
  <button onclick="setMode('cert-only')">🪪 纯证书免密 (cert-only)</button>
  <button onclick="setMode('pwd-change')">🔄 密码过期改密 (pwd-change)</button>
  <button onclick="setMode('verifycode')">🔢 图形验证码挑战 (verifycode)</button>
  <button onclick="setMode('token')">📱 动态令牌 (token)</button>
  <button onclick="setMode('sms')">💬 短信验证码 (sms)</button>
  <button onclick="setMode('err-auth')">❌ 账密错误拒绝 (err-auth)</button>
  <button onclick="setMode('err-cert')">🚫 证书过期拒绝 (err-cert)</button>
</div>
<script>
function setMode(m) {
  fetch('/api/mode?mode=' + m, { method: 'POST' }).then(() => location.reload());
}
</script>
</body>
</html>`, s.GetMode(), s.cfg.ExpectedUser, s.cfg.ExpectedPwd)
}

func (s *Server) handleAPIMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Method == http.MethodGet {
		m := r.URL.Query().Get("mode")
		if m != "" {
			s.SetMode(Mode(m))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"mode":"%s"}`, s.GetMode())
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Verbose {
		log.Printf("[MockServer] -> GET /vpn/version.xml from %s", r.RemoteAddr)
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<VERSION major="2" minor="0"/>`))
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	bodyStr := string(bodyBytes)

	values, _ := url.ParseQuery(bodyStr)
	username := values.Get("username")
	password := values.Get("password")
	encode := values.Get("encode")

	// Decode Base64 if encode=1
	rawUser, rawPwd := username, password
	if encode == "1" {
		cleanedUser := strings.ReplaceAll(strings.ReplaceAll(username, "\r", ""), "\n", "")
		cleanedPwd := strings.ReplaceAll(strings.ReplaceAll(password, "\r", ""), "\n", "")
		if u, err := base64.StdEncoding.DecodeString(cleanedUser); err == nil {
			rawUser = string(u)
		}
		if p, err := base64.StdEncoding.DecodeString(cleanedPwd); err == nil {
			rawPwd = string(p)
		}
	}

	if s.cfg.Verbose {
		log.Printf("[MockServer] -> POST /vpn/user/auth/password (encode=%s, user=%q, pwd=%q)", encode, rawUser, rawPwd)
	}

	mode := s.GetMode()
	if mode == ModeErrAuth || (s.cfg.ExpectedUser != "" && rawUser != s.cfg.ExpectedUser) {
		log.Printf("[MockServer] <- Authentication failed for %q (code: 0x8000001a)", rawUser)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x8000001a" msg="用户名或密码错误" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	sessionID := fmt.Sprintf("mock-vsg-%x", time.Now().UnixNano())
	s.mu.Lock()
	s.sessions[sessionID] = &Session{
		ID:        sessionID,
		Username:  rawUser,
		PassedPwd: true,
		CreatedAt: time.Now(),
	}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "VSG_SESSIONID",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	switch mode {
	case ModePwdOnly:
		log.Printf("[MockServer] <- Single factor login success for %q (code: 0)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModePwdCert:
		log.Printf("[MockServer] <- Two-factor challenge for %q: requesting Certificate (code: 2)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="2" msg="need cert" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModePwdChange:
		log.Printf("[MockServer] <- Password expired challenge for %q (code: 256)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="256" msg="password expired" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModeToken:
		log.Printf("[MockServer] <- Token challenge for %q (code: 4)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="4" msg="need token" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModeSMS:
		log.Printf("[MockServer] <- SMS challenge for %q (code: 8)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="8" msg="need sms" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	default:
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
	}
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("VSG_SESSIONID")
	sessionID := ""
	if err == nil {
		sessionID = sessionCookie.Value
	}

	s.mu.RLock()
	sess, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	peerCerts := r.TLS.PeerCertificates
	certDesc := "none"
	var fpStr string
	if len(peerCerts) > 0 {
		cert := peerCerts[0]
		fp := sha1.Sum(cert.Raw)
		fpStr = fmt.Sprintf("%X", fp)
		certDesc = fmt.Sprintf("Subject=%q, CN=%q, SHA1=%s", cert.Subject, cert.Subject.CommonName, fpStr)
	}

	if s.cfg.Verbose {
		log.Printf("[MockServer] -> %s /vpn/user/auth/cert (SessionID=%q, ClientCert=[%s])", r.Method, sessionID, certDesc)
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	if s.cfg.RequireCert && len(peerCerts) == 0 {
		log.Printf("[MockServer] <- Error: No client TLS certificate presented (code: 0x8000005b)")
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x8000005b" msg="未提供客户端证书" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	if exists && sess != nil {
		sess.PassedCert = true
		log.Printf("[MockServer] <- Two-factor certificate auth SUCCESS for %q (code: 0)", sess.Username)
	} else {
		log.Printf("[MockServer] <- Standalone certificate auth SUCCESS (code: 0)")
	}

	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	log.Printf("[MockServer] -> POST /vpn/user/auth/token: %s", string(body))
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

func (s *Server) handleSMS(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	log.Printf("[MockServer] -> POST /vpn/user/auth/smc: %s", string(body))
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

func (s *Server) handlePwdChange(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	log.Printf("[MockServer] -> POST /vpn/user/auth/pwdchange: %s", string(body))
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	// Switch back to pwd-only or pwd-cert after password change
	s.SetMode(ModePwdCert)
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="密码修改成功" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

func (s *Server) handleIntegration(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Verbose {
		log.Printf("[MockServer] -> GET /vpn/user/portal/intergration.xml (query: %s)", r.URL.RawQuery)
	}
	sessionCookie, _ := r.Cookie("VSG_SESSIONID")
	sid := "mock-session"
	if sessionCookie != nil {
		sid = sessionCookie.Value
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<INTERGRATION_INFO>
  <VERSION major="2" minor="0"/>
  <USER name="admin" group="default" type="user"/>
  <SESSION sid_name="VSG_SESSIONID" id="%s" detect_interval="30"/>
  <GATEWAY version="5.3.3.32"/>
  <RESOURCE_LIST>
    <TCPUDP_RESOURCE name="内网OA协同办公" protocol="tcp" mapid="1" port="8080" status="1" istcp="1">
      <TCPUDP_IP addr="10.8.0.10-10.8.0.10"/>
    </TCPUDP_RESOURCE>
    <TCPUDP_RESOURCE name="研发代码仓库 (GitLab)" protocol="tcp" mapid="2" port="443" status="1" istcp="1">
      <TCPUDP_IP addr="10.8.0.20-10.8.0.20"/>
    </TCPUDP_RESOURCE>
    <TCPUDP_RESOURCE name="核心运维堡垒机 (SSH/RDP)" protocol="tcp" mapid="3" port="22" status="1" istcp="1">
      <TCPUDP_IP addr="10.8.0.30-10.8.0.30"/>
    </TCPUDP_RESOURCE>
  </RESOURCE_LIST>
  <DNS_INFO/>
</INTERGRATION_INFO>`, sid)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Verbose {
		log.Printf("[MockServer] -> POST /vpn/user/logout")
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="logged out" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}
