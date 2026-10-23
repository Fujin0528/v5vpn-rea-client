package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// WebProxy 是仅监听回环地址的 HTTP CONNECT 代理，用于访问「端口区间」类资源。
//
// V5VPN 网关把这类资源下发成 port="1-65535"（例如堡垒机），它无法像单端口
// 资源那样映射到某个固定的本地端口。官方客户端用虚拟网卡让浏览器直接访问
// 内网 IP；本客户端不接管路由，改为在本地起一个 CONNECT 代理，浏览器经它
// 访问目标地址，每条连接都带上该资源的 MapID。
type WebProxy struct {
	GatewayIP   string
	GatewayPort int
	SessionID   string
	MapID       string
	ClientCert  *tls.Certificate
	Logger      func(level string, format string, args ...any)

	ln     net.Listener
	mu     sync.Mutex
	closed bool
}

// NewWebProxy creates a CONNECT proxy bound to one gateway resource.
func NewWebProxy(gwIP string, gwPort int, sessionID, mapID string, cert *tls.Certificate,
	logger func(string, string, ...any)) *WebProxy {
	if logger == nil {
		logger = func(string, string, ...any) {}
	}
	return &WebProxy{
		GatewayIP:   gwIP,
		GatewayPort: gwPort,
		SessionID:   sessionID,
		MapID:       mapID,
		ClientCert:  cert,
		Logger:      logger,
	}
}

// Start binds 127.0.0.1 on an ephemeral port and serves CONNECT requests.
func (p *WebProxy) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()
	go p.acceptLoop(ln)
	return ln.Addr().String(), nil
}

// Addr returns the local listen address, or "" before Start.
func (p *WebProxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Stop closes the listener; established tunnels end on their own.
func (p *WebProxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
}

func (p *WebProxy) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return
			}
			p.Logger("WARN", "网页代理接受连接失败: %v", err)
			return
		}
		go p.serve(conn)
	}
}

func (p *WebProxy) serve(client net.Conn) {
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		p.Logger("WARN", "网页代理读取请求失败: %v", err)
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(client, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	cfg := protocol.GatewayTLSConfig()
	if p.ClientCert != nil {
		cfg.Certificates = []tls.Certificate{*p.ClientCert}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	gwAddr := fmt.Sprintf("%s:%d", p.GatewayIP, p.GatewayPort)
	gw, err := tls.DialWithDialer(dialer, "tcp", gwAddr, cfg)
	if err != nil {
		p.Logger("ERROR", "网页代理连接网关失败: %v", err)
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer gw.Close()

	connectReq := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nCookie: MapID=%s; VSG_SESSIONID=%s\r\nUser-Agent: LeadSec VPN Client\r\n\r\n",
		target, target, p.MapID, p.SessionID)
	if _, err := gw.Write([]byte(connectReq)); err != nil {
		p.Logger("ERROR", "网页代理发送 CONNECT 失败: %v", err)
		return
	}

	gwReader := bufio.NewReader(gw)
	resp, err := http.ReadResponse(gwReader, req)
	if err != nil {
		p.Logger("ERROR", "网页代理读取网关响应失败: %v", err)
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if resp.StatusCode != http.StatusOK {
		p.Logger("WARN", "网关拒绝网页代理隧道 %s: %s", target, resp.Status)
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	p.Logger("INFO", "网页代理隧道已建立: %s", target)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(gw, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, gwReader)
		done <- struct{}{}
	}()
	// 任一侧结束即释放连接：浏览器关闭标签页时另一侧通常不会主动断开。
	<-done
}
