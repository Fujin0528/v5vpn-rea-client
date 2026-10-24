package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// gatewayCert 生成一张自签服务端证书：WebProxy 的 TLS 配置放行自签证书
// （protocol.GatewayTLSConfig 的 InsecureSkipVerify），测试网关用它建 TLS。
func gatewayCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "test-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// connectGateway 是一台只会说 CONNECT 的假网关：按 allow 决定放行或拒绝，
// 放行后把隧道数据原样回显。它记录收到的目标与 Cookie 供测试断言。
type connectGateway struct {
	t    *testing.T
	ln   net.Listener
	IP   string
	Port int

	mu        sync.Mutex
	targets   []string
	cookies   []string
	peerCerts int

	allow       bool
	requireCert bool

	handlerWG   sync.WaitGroup
	firstClosed chan struct{}
	closeOnce   sync.Once
}

// startConnectGateway 启动 TLS 假网关。requireCert 时网关要求客户端呈递
// 证书（校验 WebProxy 的 mTLS 分支）。
func startConnectGateway(t *testing.T, allow, requireCert bool) *connectGateway {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{gatewayCert(t)}}
	if requireCert {
		cfg.ClientAuth = tls.RequireAnyClientCert
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	g := &connectGateway{
		t:           t,
		ln:          ln,
		allow:       allow,
		requireCert: requireCert,
		firstClosed: make(chan struct{}),
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	g.IP, g.Port = host, port

	t.Cleanup(func() { _ = ln.Close() })

	g.handlerWG.Add(1)
	go func() {
		defer g.handlerWG.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			g.handlerWG.Add(1)
			go func() {
				defer g.handlerWG.Done()
				g.handle(conn)
			}()
		}
	}()
	return g
}

// handle 处理一条网关侧连接：读 CONNECT 请求，记录并应答，放行则回显数据。
func (g *connectGateway) handle(conn net.Conn) {
	defer conn.Close()
	defer g.closeOnce.Do(func() { close(g.firstClosed) })

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if tc, ok := conn.(*tls.Conn); ok && g.requireCert {
		st := tc.ConnectionState()
		g.mu.Lock()
		g.peerCerts = len(st.PeerCertificates)
		g.mu.Unlock()
	}

	g.mu.Lock()
	g.targets = append(g.targets, req.Host)
	g.cookies = append(g.cookies, req.Header.Get("Cookie"))
	g.mu.Unlock()

	if !g.allow {
		_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")

	// 回显：客户端发出的每个字节都送回去，直到它断开。
	buf := make([]byte, 4096)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (g *connectGateway) lastTarget() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.targets) == 0 {
		return ""
	}
	return g.targets[len(g.targets)-1]
}

func (g *connectGateway) lastCookie() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.cookies) == 0 {
		return ""
	}
	return g.cookies[len(g.cookies)-1]
}

func (g *connectGateway) peerCertCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peerCerts
}

// connectThrough 以客户端身份穿过 WebProxy 建立一条 CONNECT 隧道，
// 返回已读完 200 响应的连接与 bufio reader。
func connectThrough(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(c)
	req := &http.Request{Method: http.MethodConnect}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = c.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		t.Fatalf("CONNECT %s via proxy: status %s, want 200", target, resp.Status)
	}
	return c, br
}

func TestWebProxyTunnelRelaysData(t *testing.T) {
	gw := startConnectGateway(t, true, false)
	wp := NewWebProxy(gw.IP, gw.Port, "sess-123", "map-456", nil, []string{"10.10.20.15"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer wp.Stop()

	c, br := connectThrough(t, addr, "10.10.20.15:443")
	defer c.Close()

	payload := "hello-tunnel-payload"
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	if target := gw.lastTarget(); target != "10.10.20.15:443" {
		t.Fatalf("gateway saw CONNECT target %q, want 10.10.20.15:443", target)
	}
	cookie := gw.lastCookie()
	if !strings.Contains(cookie, "MapID=map-456") {
		t.Fatalf("gateway cookie missing MapID: %q", cookie)
	}
	if !strings.Contains(cookie, "VSG_SESSIONID=sess-123") {
		t.Fatalf("gateway cookie missing VSG_SESSIONID: %q", cookie)
	}
}

func TestWebProxyDefaultsToPort443(t *testing.T) {
	gw := startConnectGateway(t, true, false)
	wp := NewWebProxy(gw.IP, gw.Port, "s", "m", nil, []string{"10.10.20.15"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer wp.Stop()

	c, _ := connectThrough(t, addr, "10.10.20.15")
	c.Close()

	if target := gw.lastTarget(); target != "10.10.20.15:443" {
		t.Fatalf("gateway saw target %q, want 10.10.20.15:443 (default port)", target)
	}
}

func TestWebProxyPresentsClientCert(t *testing.T) {
	gw := startConnectGateway(t, true, true)
	cert := clientCertForTest(t)
	wp := NewWebProxy(gw.IP, gw.Port, "s", "m", cert, []string{"10.10.20.15"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer wp.Stop()

	c, _ := connectThrough(t, addr, "10.10.20.15:443")
	c.Close()

	if n := gw.peerCertCount(); n != 1 {
		t.Fatalf("gateway saw %d peer certificates, want 1", n)
	}
}

func TestWebProxyRejectsNonConnect(t *testing.T) {
	gw := startConnectGateway(t, true, false)
	wp := NewWebProxy(gw.IP, gw.Port, "s", "m", nil, []string{"10.10.20.15"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer wp.Stop()

	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("plain GET through proxy: status %s, want 405", resp.Status)
	}
	if gw.lastTarget() != "" {
		t.Fatalf("proxy forwarded non-CONNECT request to gateway: target %q", gw.lastTarget())
	}
}

func TestWebProxyGatewayRefusalYields502(t *testing.T) {
	gw := startConnectGateway(t, false, false)
	wp := NewWebProxy(gw.IP, gw.Port, "s", "m", nil, []string{"10.10.20.15"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer wp.Stop()

	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT 10.10.20.15:443 HTTP/1.1\r\nHost: 10.10.20.15:443\r\n\r\n")

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	req := &http.Request{Method: http.MethodConnect}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("refused tunnel: status %s, want 502", resp.Status)
	}
}

func TestWebProxyStopClosesListener(t *testing.T) {
	gw := startConnectGateway(t, true, false)
	wp := NewWebProxy(gw.IP, gw.Port, "s", "m", nil, []string{"10.10.20.15"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if wp.Addr() == "" {
		t.Fatal("Addr() empty right after Start")
	}
	wp.Stop()
	if wp.Addr() != "" {
		t.Fatalf("Addr() = %q after Stop, want empty", wp.Addr())
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("listener still accepting connections after Stop")
	}
}

func TestWebProxyTunnelEndsWhenClientCloses(t *testing.T) {
	gw := startConnectGateway(t, true, false)
	wp := NewWebProxy(gw.IP, gw.Port, "s", "m", nil, []string{"10.10.20.15"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer wp.Stop()

	c, _ := connectThrough(t, addr, "10.10.20.15:443")
	c.Close()

	// 客户端断开后，代理应关闭网关侧连接，网关的回显循环随之结束。
	select {
	case <-gw.firstClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway handler still running 5s after client closed")
	}
}

// clientCertForTest 生成自签客户端证书（mTLS 分支用）。
func clientCertForTest(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{CommonName: "webproxy-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestWebProxyRejectsOffResourceTarget 守卫隧道白名单：代理在回环上对
// 同机所有进程可达，而 CONNECT 会自动携带用户会话凭据——白名单之外的
// 目标必须 403，且请求根本不该到达网关。
func TestWebProxyRejectsOffResourceTarget(t *testing.T) {
	gw := startConnectGateway(t, true, false)
	wp := NewWebProxy(gw.IP, gw.Port, "sess", "map", nil, []string{"10.10.20.15"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer wp.Stop()

	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT 192.168.1.99:445 HTTP/1.1\r\nHost: 192.168.1.99:445\r\n\r\n")

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	req := &http.Request{Method: http.MethodConnect}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("off-resource CONNECT: status %s, want 403", resp.Status)
	}
	if gw.lastTarget() != "" {
		t.Fatalf("off-resource CONNECT reached gateway: target %q", gw.lastTarget())
	}
}

// TestWebProxyWildcardAndDynamicAllowlist 覆盖通配规则与运行中同步：
// 尾部 * 命中同网段任意主机；SetAllowedHosts 后新目标立即生效。
func TestWebProxyWildcardAndDynamicAllowlist(t *testing.T) {
	gw := startConnectGateway(t, true, false)
	wp := NewWebProxy(gw.IP, gw.Port, "s", "m", nil, []string{"10.10.20.*"}, nil)
	addr, err := wp.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer wp.Stop()

	// 通配内：10.10.20.99 命中 10.10.20.*。
	c, _ := connectThrough(t, addr, "10.10.20.99:443")
	c.Close()

	// 通配外：192.168.5.5 被拒（403）。
	c2, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_, _ = io.WriteString(c2, "CONNECT 192.168.5.5:443 HTTP/1.1\r\nHost: 192.168.5.5:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c2), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outside wildcard: status %s, want 403", resp.Status)
	}
	c2.Close()

	// 用户补充地址变更后同步：新地址立即放行。
	wp.SetAllowedHosts([]string{"10.10.20.*", "10.99.0.1"})
	c3, _ := connectThrough(t, addr, "10.99.0.1:443")
	c3.Close()
}
