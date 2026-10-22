package service

// atrust_proxy_test.go — 本地代理层的测试。
//
// 这一层做三件事：**本地监听 → 建隧道 → 双向转发**。测试的重点因此是
// 接线正确性，而不是协议细节（帧编码在 internal/atrust 里验）。
//
// 关键设计：用一个**真的** TCP 服务当"网关"，再注入一个把目标接到它的
// dialer。这样两端都是真 socket，io.Copy 的关闭传播、半关闭、并发
// 都能被真实触发；如果换成纯 mock 的 net.Conn，最容易出错的
// "一侧关闭后另一侧还在等"就测不出来了。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/atrust"
)

// dialerFunc 让普通函数满足 tunnelDialer。
type dialerFunc func(ctx context.Context, host string, port int) (net.Conn, error)

func (f dialerFunc) DialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	return f(ctx, host, port)
}

// directDialer 直接把目标当作真实地址去连。
//
// 测试里资源的 RemoteIP 填 127.0.0.1、端口填 echo 服务的端口，
// 于是"隧道"变成一次本地直连——代理的接线逻辑因此可以脱离 441 验证。
func directDialer() tunnelDialer {
	return dialerFunc(func(ctx context.Context, host string, port int) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	})
}

// echoServer 起一个本地 echo 服务。
type echoServer struct {
	ln   net.Listener
	port int
	wg   sync.WaitGroup
}

func startEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 echo 服务失败: %v", err)
	}
	s := &echoServer{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(s.stop)
	return s
}

func (s *echoServer) stop() {
	_ = s.ln.Close()
	s.wg.Wait()
}

// ---------- 跳过规则 ----------

// TestATrustProxySkipsUnsupported 验证不支持的资源被保留但不映射。
//
// 「保留」很重要：用户在列表里要看到这条资源存在、只是暂不支持，
// 而不是让它凭空消失。
func TestATrustProxySkipsUnsupported(t *testing.T) {
	p := NewATrustProxyWithDialer(directDialer(), nil)
	defer p.Stop()

	items := p.Start([]atrust.Resource{
		{Name: "UDP 资源", Protocol: "udp", RemoteIP: "10.0.0.1", RemotePort: "53"},
		{Name: "通配端口", Protocol: "tcp", RemoteIP: "10.20.0.0/16", RemotePort: "*"},
		{Name: "零端口", Protocol: "tcp", RemoteIP: "10.20.1.0", RemotePort: "0"},
		{Name: "无地址", Protocol: "tcp", RemoteIP: "", RemotePort: "443"},
	})

	if len(items) != 4 {
		t.Fatalf("应当保留全部 4 条资源，实际 %d 条", len(items))
	}
	for _, r := range items {
		if r.LocalProxy != "" {
			t.Errorf("%s 不应被映射，却得到 %q", r.Name, r.LocalProxy)
		}
	}
	if n := p.ActiveListeners(); n != 0 {
		t.Errorf("不应有监听，实际 %d 个", n)
	}
}

// TestATrustProxyPortDedup 验证同一目标只监听一次。
//
// 资源树里同一目标常有多条规则（不同分组），不合并会白占端口。
func TestATrustProxyPortDedup(t *testing.T) {
	p := NewATrustProxyWithDialer(directDialer(), nil)
	defer p.Stop()

	items := p.Start([]atrust.Resource{
		{Name: "A", Protocol: "tcp", RemoteIP: "10.0.0.1", RemotePort: "18099"},
		{Name: "B", Protocol: "tcp", RemoteIP: "10.0.0.1", RemotePort: "18099"},
	})

	if len(items) != 2 {
		t.Fatalf("资源数 = %d, want 2", len(items))
	}
	if items[0].LocalProxy == "" || items[0].LocalProxy != items[1].LocalProxy {
		t.Errorf("同一目标应复用监听: %q vs %q", items[0].LocalProxy, items[1].LocalProxy)
	}
	if n := p.ActiveListeners(); n != 1 {
		t.Errorf("监听数 = %d, want 1（同一目标应复用）", n)
	}
}

// TestATrustProxyPortFallback 验证目标端口被占用时退回随机端口。
func TestATrustProxyPortFallback(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port

	p := NewATrustProxyWithDialer(directDialer(), nil)
	defer p.Stop()

	items := p.Start([]atrust.Resource{
		{Name: "占用端口", Protocol: "tcp", RemoteIP: "10.0.0.1", RemotePort: fmt.Sprint(busyPort)},
	})

	if len(items) != 1 || items[0].LocalProxy == "" {
		t.Fatalf("应退回随机端口并成功监听，实际 %+v", items)
	}
	_, portStr, _ := net.SplitHostPort(items[0].LocalProxy)
	if portStr == fmt.Sprint(busyPort) {
		t.Errorf("端口 %s 已被占用，不应复用", portStr)
	}
}

// TestATrustProxyStopReleasesPort 验证 Stop 之后端口真的被释放。
//
// 这条比"Stop 没 panic"有意义得多：监听没关的话，下次登录会绑定失败，
// 用户看到的是"重连之后资源全不可用"。
func TestATrustProxyStopReleasesPort(t *testing.T) {
	p := NewATrustProxyWithDialer(directDialer(), nil)
	items := p.Start([]atrust.Resource{
		{Name: "X", Protocol: "tcp", RemoteIP: "10.0.0.1", RemotePort: "18081"},
	})
	if len(items) != 1 || items[0].LocalProxy == "" {
		t.Fatalf("监听未建立: %+v", items)
	}
	addr := items[0].LocalProxy

	p.Stop()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Stop 后端口 %s 仍被占用: %v", addr, err)
	}
	_ = ln.Close()

	if n := p.ActiveListeners(); n != 0 {
		t.Errorf("Stop 后监听数 = %d, want 0", n)
	}
}

// TestATrustProxyStartAfterStop 验证 Stop 之后 Start 不会复活监听。
//
// 场景：登出（Stop）与资源刷新（Start）在 UI 上可能几乎同时发生。
// 已经关闭的 proxy 如果能重新监听，那些端口就没人负责关了。
func TestATrustProxyStartAfterStop(t *testing.T) {
	p := NewATrustProxyWithDialer(directDialer(), nil)
	p.Stop()

	items := p.Start([]atrust.Resource{
		{Name: "X", Protocol: "tcp", RemoteIP: "10.0.0.1", RemotePort: "18082"},
	})
	if items[0].LocalProxy != "" {
		t.Errorf("已关闭的 proxy 不应再建立监听，却得到 %q", items[0].LocalProxy)
	}
}

// ---------- 数据转发 ----------

// TestProxyForwardsBytes 验证端到端双向转发。
//
// 这是代理层唯一真正重要的断言：从本地监听写进去的字节，要原样到目标；
// 目标回来的字节，要原样到本地。上面所有测试加起来都覆盖不了它。
func TestProxyForwardsBytes(t *testing.T) {
	echo := startEchoServer(t)

	p := NewATrustProxyWithDialer(directDialer(), nil)
	defer p.Stop()

	items := p.Start([]atrust.Resource{
		{Name: "echo", Protocol: "tcp", RemoteIP: "127.0.0.1", RemotePort: fmt.Sprint(echo.port)},
	})
	if len(items) != 1 || items[0].LocalProxy == "" {
		t.Fatalf("监听未建立: %+v", items)
	}

	conn, err := net.DialTimeout("tcp", items[0].LocalProxy, 3*time.Second)
	if err != nil {
		t.Fatalf("连接本地代理失败: %v", err)
	}
	defer conn.Close()

	want := bytes.Repeat([]byte("tunnel!"), 4096) // ~28KB，跨过多个 TCP 段
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读取回显失败（已收到 %d/%d 字节）: %v", 0, len(want), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("回显内容不一致：长度 %d vs %d", len(got), len(want))
	}
}

// TestProxyClosesWhenTunnelFails 验证 tunnel 建立失败时本地连接被关闭。
//
// 不关闭的话，客户端会一直等一个永远不会来的响应——
// 表现为"连上了但网页一直转圈"，比直接报错难查得多。
func TestProxyClosesWhenTunnelFails(t *testing.T) {
	var attempts atomic.Int32
	dialer := dialerFunc(func(ctx context.Context, host string, port int) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("模拟隧道失败")
	})

	p := NewATrustProxyWithDialer(dialer, nil)
	defer p.Stop()

	items := p.Start([]atrust.Resource{
		{Name: "X", Protocol: "tcp", RemoteIP: "10.0.0.9", RemotePort: "18084"},
	})
	if items[0].LocalProxy == "" {
		t.Fatal("监听未建立")
	}

	conn, err := net.DialTimeout("tcp", items[0].LocalProxy, 3*time.Second)
	if err != nil {
		t.Fatalf("连接本地代理失败: %v", err)
	}
	defer conn.Close()

	// 隧道建不起来时，读应当很快返回 EOF/错误，而不是挂到测试超时。
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("隧道失败后本地连接没有被关闭")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("隧道失败后本地连接一直挂着（读超时）")
	}
	if attempts.Load() != 1 {
		t.Errorf("DialTCP 调用次数 = %d, want 1", attempts.Load())
	}
}

// TestProxyPropagatesClose 验证本地关闭会传播到目标一侧。
//
// 典型场景是 HTTP 这类"客户端写完就挂断"的协议。如果代理只关本地、
// 不关隧道，目标会一直挂在那里等数据，网关侧也会留一条半开连接，
// 累积起来就是资源耗尽。这里让目标服务在读到 EOF 时发一个信号，
// 断言那个信号确实到了。
func TestProxyPropagatesClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// 目标服务把每次连接的结束时间点报出来。
	targetClosed := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c) // 读到 EOF 为止
		targetClosed <- struct{}{}
	}()

	p := NewATrustProxyWithDialer(directDialer(), nil)
	defer p.Stop()

	port := ln.Addr().(*net.TCPAddr).Port
	items := p.Start([]atrust.Resource{
		{Name: "X", Protocol: "tcp", RemoteIP: "127.0.0.1", RemotePort: fmt.Sprint(port)},
	})
	if items[0].LocalProxy == "" {
		t.Fatal("监听未建立")
	}

	conn, err := net.DialTimeout("tcp", items[0].LocalProxy, 3*time.Second)
	if err != nil {
		t.Fatalf("连接本地代理失败: %v", err)
	}
	_, _ = conn.Write([]byte("hello"))
	_ = conn.Close()

	select {
	case <-targetClosed:
	case <-time.After(10 * time.Second):
		t.Fatal("本地连接已关闭，但目标一侧没有收到 EOF——代理没有把关闭传播过去")
	}
}

// TestProxyConcurrentConnections 验证并发接入不会互相卡死。
func TestProxyConcurrentConnections(t *testing.T) {
	echo := startEchoServer(t)

	p := NewATrustProxyWithDialer(directDialer(), nil)
	defer p.Stop()

	items := p.Start([]atrust.Resource{
		{Name: "echo", Protocol: "tcp", RemoteIP: "127.0.0.1", RemotePort: fmt.Sprint(echo.port)},
	})
	if items[0].LocalProxy == "" {
		t.Fatal("监听未建立")
	}

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", items[0].LocalProxy, 3*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()

			msg := []byte(fmt.Sprintf("conn-%d", i))
			if _, err := conn.Write(msg); err != nil {
				errs <- err
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("conn-%d 回显错乱: %q", i, got)
			}
		}(i)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("并发转发超时——可能有连接互相卡住了")
	}
	close(errs)
	for err := range errs {
		t.Errorf("并发连接失败: %v", err)
	}
}

// ---------- 端口解析 ----------

// TestParsePortLoose 覆盖端口字段的各种形态。
func TestParsePortLoose(t *testing.T) {
	cases := map[string]int{
		"443":      443,
		" 8443 ":   8443,
		"":         0,
		"*":        0,
		"443;8443": 443,
		"443,8443": 443,
		"abc":      0,
		"-1":       -1,
	}
	for in, want := range cases {
		if got := parsePortLoose(in); got != want {
			t.Errorf("parsePortLoose(%q) = %d, want %d", in, got, want)
		}
	}
}
