package service

// atrust_proxy.go — 把 aTrust 资源映射成本地监听端口。
//
// 这一层的职责很窄：**本地监听 → 经由 aTrust 隧道转发 → 目标**。
// 不做路由决策（那是 internal/atrust/route.go 的事），不做协议转换，
// 只把 net.Conn 两端接起来。
//
// 为什么需要它：aTrust 的数据面是"按需建连"的——每条到内网的 TCP 流
// 都要单独做一次隧道认证。用户不会手动去建这些连接，所以必须有人在
// 本地监听，等应用连上来时再触发建连。这也是 V5VPN 侧 ProxyManager
// 的做法（internal/proxy/tunnel.go），两个后端在这一点上形态一致，
// 界面可以直接复用同一套"本地代理地址"展示。
//
// 与 V5VPN 侧的关键差异：
//
//	V5VPN   ：本地监听 → HTTP CONNECT over TLS → 网关（每条连接一次）
//	aTrust  ：本地监听 → 二进制隧道帧 over TLS → 网关（每条连接一次）
//
// 相同点：都是"一条本地 TCP 连接对应一条网关连接"，因此不需要在本地
// 做多路复用或流量整形。

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/atrust"
)

// atrustDialTimeout 限制单条隧道连接的建立时间。
//
// 比控制面的 30s 短：用户在等一个网页打开，等 30 秒才失败没有意义。
const atrustDialTimeout = 20 * time.Second

// ATrustProxy 管理 aTrust 资源的本地监听。
type ATrustProxy struct {
	client *atrust.Client
	logf   func(format string, args ...any)

	mu        sync.Mutex
	listeners map[string]net.Listener // key = 资源标识
	closed    bool
	wg        sync.WaitGroup
}

// NewATrustProxy 创建代理管理器。
func NewATrustProxy(client *atrust.Client, logf func(string, ...any)) *ATrustProxy {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ATrustProxy{
		client:    client,
		logf:      logf,
		listeners: map[string]net.Listener{},
	}
}

// Start 为每条 TCP 资源起一个本地监听，返回带 LocalProxy 的资源列表。
//
// 只处理 tcp 资源：aTrust 的 UDP 走 L3 数据面（0x14/0x94 IPv4 小包），
// 需要用户态 IP 栈，不在当前实现范围内。这类资源会保留在列表里但
// LocalProxy 为空——界面据此显示"暂不支持"，而不是给一个连不上的地址。
//
// 同一个资源可能有多条 addressList（域名 + IP），这里**每条起一个监听**：
// 它们指向不同目标，合并会丢失语义。
func (p *ATrustProxy) Start(resources []atrust.Resource) []atrust.Resource {
	out := make([]atrust.Resource, 0, len(resources))

	for _, r := range resources {
		if !strings.EqualFold(r.Protocol, "tcp") {
			p.logf("跳过 %s [%s]：数据面目前只支持 TCP", r.Name, r.Protocol)
			out = append(out, r)
			continue
		}
		if r.RemoteIP == "" {
			out = append(out, r)
			continue
		}

		port := parsePortLoose(r.RemotePort)
		if port <= 0 {
			// 资源树里 port "0" 表示"所有端口"。对这类规则无法起一个
			// 有意义的固定监听——真实客户端是配合透明代理/路由表工作的。
			// 保留条目但标记为未映射。
			p.logf("跳过 %s：端口为通配（%q），需要透明代理支持", r.Name, r.RemotePort)
			out = append(out, r)
			continue
		}

		key := fmt.Sprintf("%s:%d", r.RemoteIP, port)
		if ln, err := p.listen(key, r.RemoteIP, port); err != nil {
			p.logf("为 %s 建立本地监听失败: %v", key, err)
		} else {
			r.LocalProxy = ln.Addr().String()
			r.Status = "Listening"
			p.logf("本地代理就绪: %s [%s] -> %s", r.Name, key, r.LocalProxy)
		}
		out = append(out, r)
	}
	return out
}

// listen 起一个本地监听并为每条接入连接建隧道。
func (p *ATrustProxy) listen(key, targetHost string, targetPort int) (net.Listener, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("proxy 已关闭")
	}
	if ln, ok := p.listeners[key]; ok {
		p.mu.Unlock()
		return ln, nil // 同一目标已监听，复用
	}
	p.mu.Unlock()

	// 优先用目标端口本身（用户看到的地址更直观），被占用则退回随机端口。
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.listeners[key] = ln
	p.mu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.acceptLoop(ln, targetHost, targetPort)
	}()
	return ln, nil
}

// acceptLoop 接受本地连接并逐条转发。
func (p *ATrustProxy) acceptLoop(ln net.Listener, targetHost string, targetPort int) {
	for {
		local, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return
			}
			// 临时错误（如 fd 耗尽）不应当让整个监听退出。
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			p.logf("本地监听取接受失败（%s）：%v", ln.Addr(), err)
			return
		}
		go p.forward(local, targetHost, targetPort)
	}
}

// forward 把一条本地连接接到隧道上。
func (p *ATrustProxy) forward(local net.Conn, targetHost string, targetPort int) {
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), atrustDialTimeout)
	defer cancel()

	remote, err := p.client.DialTCP(ctx, targetHost, targetPort)
	if err != nil {
		p.logf("建立隧道失败 (%s:%d): %v", targetHost, targetPort, err)
		return
	}
	defer remote.Close()

	p.logf("隧道已建立: 本地 %s -> %s:%d", local.RemoteAddr(), targetHost, targetPort)

	// 双向转发。两个方向都要等待，但**不能无限等**：
	// 一侧关闭后另一侧可能永远等不到数据，所以要主动中断。
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(remote, local)
		p.logf("本地→隧道 结束（%d 字节）", n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(local, remote)
		p.logf("隧道→本地 结束（%d 字节）", n)
		done <- struct{}{}
	}()

	<-done
	// 第一方向结束后，关掉两端让另一个方向立刻返回，而不是挂到超时。
	_ = local.Close()
	_ = remote.Close()
	<-done
}

// Stop 关闭全部监听并等待转发协程退出。
func (p *ATrustProxy) Stop() {
	p.mu.Lock()
	p.closed = true
	lns := make([]net.Listener, 0, len(p.listeners))
	for k, ln := range p.listeners {
		lns = append(lns, ln)
		p.logf("关闭本地代理 %s", k)
	}
	p.listeners = map[string]net.Listener{}
	p.mu.Unlock()

	for _, ln := range lns {
		_ = ln.Close()
	}
	p.wg.Wait()
}

// ActiveListeners 返回当前监听数量，供状态展示。
func (p *ATrustProxy) ActiveListeners() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.listeners)
}

// parsePortLoose 把资源里的端口字段转成整数。
//
// 资源树里的端口可能是 "443"、"443;8443"（多端口）或 "*"，
// 这里只取第一个可解析的数字。
func parsePortLoose(s string) int {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return 0
	}
	if i := strings.IndexAny(s, ";,"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	n, _ := strconv.Atoi(s)
	return n
}
