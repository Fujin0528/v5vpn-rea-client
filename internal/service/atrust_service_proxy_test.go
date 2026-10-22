package service

// atrust_service_proxy_test.go — 资源加载 → 本地代理这条链的集成测试。
//
// 和 atrust_service_test.go 的分工：那边验协议对接与状态形状，这边验
// **代理的生命周期**——它属于 ATrustService 的职责，但过去完全没有覆盖。
//
// 具体守三件曾经/差点出事的事：
//  1. 死锁：loadResources 曾在持锁状态下再次取锁，测试挂 600 秒才被发现
//  2. 刷新不换端口：新 proxy 在旧监听未释放时启动，只能退回随机端口，
//     用户配好的本地地址每次刷新都变
//  3. 登出不释放端口：下次登录绑不上，表现为"重连后资源全不可用"
//
// 数据面用假 dialer 注入，因此这些测试不连 441、不需要真网关。

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingDialer 是一个可计数的假数据面：不真的建连，只记录被请求的目标。
type blockingDialer struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (d *blockingDialer) DialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	d.calls.Add(1)
	if d.fail.Load() {
		return nil, fmt.Errorf("模拟隧道失败")
	}
	// 返回一个本地回环连接，让转发协程有东西可拷贝。
	// 连不上也无所谓——测试只关心代理有没有被正确装配。
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", "127.0.0.1:1")
}

// tcpResource 构造一条最小资源条目。
//
// 当前用例都通过 fakeGateway 的资源树下发资源，这个 helper 留给
// 需要直接构造 Resource 的场景。
func tcpResource(name, host string, port int) map[string]any {
	return map[string]any{
		"name":        name,
		"protocol":    "tcp",
		"host":        host,
		"port":        port,
		"nodeGroupId": "ng",
	}
}

// newServiceWithFakeDialer 造一个带假数据面的服务，并让它指向给定网关。
func newServiceWithFakeDialer(t *testing.T, g *fakeGateway) (*ATrustService, *fakeHost, *blockingDialer) {
	t.Helper()
	host := newFakeHost(g.profile())
	svc := NewATrustService(host)
	d := &blockingDialer{}
	svc.proxyDialer = d
	return svc, host, d
}

// TestATrustLoginStartsProxy 验证登录后资源被映射到本地端口。
func TestATrustLoginStartsProxy(t *testing.T) {
	g := newFakeGateway(t)
	svc, _, _ := newServiceWithFakeDialer(t, g)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}

	waitFor(t, func() bool {
		return svc.GetStatus()["resourceState"] == string(ResourceReady)
	})

	resources := svc.Resources
	if len(resources) != 2 {
		t.Fatalf("资源数 = %d, want 2: %+v", len(resources), resources)
	}
	for _, r := range resources {
		if r.LocalProxy == "" {
			t.Errorf("%s 没有本地代理地址", r.Name)
			continue
		}
		// 端口必须是活的：能连上才算真的映射成功。
		conn, err := net.DialTimeout("tcp", r.LocalProxy, 2*time.Second)
		if err != nil {
			t.Errorf("%s 的本地代理 %s 不可连接: %v", r.Name, r.LocalProxy, err)
			continue
		}
		_ = conn.Close()
	}
}

// TestATrustLoadResourcesDoesNotDeadlock 是那个 600 秒挂起的回归测试。
//
// 症状：登录后 GetStatus 永远返回不了，整个 UI 卡死。根因是
// loadResources 在已经持锁的情况下再次 Lock（sync.Mutex 不可重入）。
// 这里用**带超时的调用**去探测：真死锁时测试会在几秒内失败，
// 而不是挂到 go test 的十分钟上限。
func TestATrustLoadResourcesDoesNotDeadlock(t *testing.T) {
	g := newFakeGateway(t)
	svc, _, _ := newServiceWithFakeDialer(t, g)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}

	// 等资源加载完成，这一步最接近死锁现场：loadResources 正在跑，
	// 同时有别的协程在读状态。
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			if svc.GetStatus()["resourceState"] == string(ResourceReady) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("资源加载期间取状态被永久阻塞——loadResources 又发生死锁了")
	}

	// 加载完成后再取一次，确认锁没有被吐出去。
	got := make(chan map[string]any, 1)
	go func() { got <- svc.GetStatus() }()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("资源加载完成后取状态仍然阻塞")
	}
}

// TestATrustRefreshKeepsLocalPorts 验证刷新前后本地端口不变。
//
// 这条是**真实缺陷的回归测试**：曾经的实现先起新 proxy、再停旧的。
// 两者抢同一批端口，新的必然抢不到，只能静默退回随机端口——用户会
// 看到"每刷新一次，本地代理地址就全变了"，已经配好的客户端立刻失效。
func TestATrustRefreshKeepsLocalPorts(t *testing.T) {
	g := newFakeGateway(t)
	svc, _, _ := newServiceWithFakeDialer(t, g)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	waitFor(t, func() bool { return svc.GetStatus()["resourceState"] == string(ResourceReady) })

	before := make(map[string]string, len(svc.Resources))
	for _, r := range svc.Resources {
		before[r.RemoteIP] = r.LocalProxy
	}

	if _, err := svc.RefreshResources(); err != nil {
		t.Fatalf("RefreshResources 失败: %v", err)
	}

	for _, r := range svc.Resources {
		old, ok := before[r.RemoteIP]
		if !ok {
			t.Errorf("刷新后出现了新目标 %s，测试前提不成立", r.RemoteIP)
			continue
		}
		if r.LocalProxy != old {
			t.Errorf("%s 的本地地址在刷新后从 %q 变成了 %q——刷新不应改变用户可见的端口",
				r.RemoteIP, old, r.LocalProxy)
		}
	}
}

// TestATrustRefreshReplacesProxy 验证刷新后旧监听被释放、新的接管。
//
// 与上一条互补：端口不变意味着"旧的先停、新的后起"，
// 那就要确认旧的**确实**停了，否则新 proxy 的监听会和它重叠。
func TestATrustRefreshReplacesProxy(t *testing.T) {
	g := newFakeGateway(t)
	svc, _, _ := newServiceWithFakeDialer(t, g)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	waitFor(t, func() bool { return svc.GetStatus()["resourceState"] == string(ResourceReady) })

	svc.mu.Lock()
	first := svc.proxy
	svc.mu.Unlock()
	if first == nil {
		t.Fatal("登录后没有建立代理")
	}

	if _, err := svc.RefreshResources(); err != nil {
		t.Fatalf("RefreshResources 失败: %v", err)
	}

	svc.mu.Lock()
	second := svc.proxy
	svc.mu.Unlock()
	if second == nil {
		t.Fatal("刷新后没有代理")
	}
	if second == first {
		t.Error("刷新后仍在用同一个 proxy——资源变更不会生效")
	}
	// 旧 proxy 必须已关闭：ActiveListeners 归零。
	if n := first.ActiveListeners(); n != 0 {
		t.Errorf("旧 proxy 仍有 %d 个监听未释放", n)
	}
	if n := second.ActiveListeners(); n == 0 {
		t.Error("新 proxy 没有任何监听")
	}
}

// TestATrustLogoutReleasesPorts 验证登出后本地端口全部释放。
//
// 不释放的话，下次登录会绑不上同一批端口，只能退回随机端口；
// 用户的客户端配置会莫名其妙失效。
func TestATrustLogoutReleasesPorts(t *testing.T) {
	g := newFakeGateway(t)
	svc, _, _ := newServiceWithFakeDialer(t, g)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	waitFor(t, func() bool { return svc.GetStatus()["resourceState"] == string(ResourceReady) })

	svc.mu.Lock()
	proxy := svc.proxy
	svc.mu.Unlock()
	addr := ""
	for _, r := range svc.Resources {
		if r.LocalProxy != "" {
			addr = r.LocalProxy
			break
		}
	}
	if addr == "" {
		t.Fatal("没有可用的本地代理地址")
	}

	if _, err := svc.Logout(); err != nil {
		t.Fatalf("Logout 失败: %v", err)
	}

	if n := proxy.ActiveListeners(); n != 0 {
		t.Errorf("登出后仍有 %d 个监听", n)
	}
	// 端口必须真的可以重新绑定。
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("登出后端口 %s 仍被占用: %v", addr, err)
	}
	_ = ln.Close()
}

// TestATrustLoginReplacesStaleSession 验证重复登录会拆掉旧会话的代理。
//
// 用户在界面上重复点"连接"是常见操作。旧代理不拆，端口会被占着，
// 新会话只能拿到随机端口。
func TestATrustLoginReplacesStaleSession(t *testing.T) {
	g := newFakeGateway(t)
	svc, _, _ := newServiceWithFakeDialer(t, g)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("首次 Login 失败: %v", err)
	}
	waitFor(t, func() bool { return svc.GetStatus()["resourceState"] == string(ResourceReady) })

	svc.mu.Lock()
	oldProxy := svc.proxy
	svc.mu.Unlock()

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("再次 Login 失败: %v", err)
	}
	waitFor(t, func() bool { return svc.GetStatus()["resourceState"] == string(ResourceReady) })

	if n := oldProxy.ActiveListeners(); n != 0 {
		t.Errorf("旧会话的代理仍有 %d 个监听未释放", n)
	}
}

// TestATrustResourceLoadFailureKeepsSession 验证资源拉取失败不清会话。
//
// 会话本身是有效的，用户应当能在资源表上点重试。把整个会话判死
// 会让一次网络抖动变成"必须重新登录"。
func TestATrustResourceLoadFailureKeepsSession(t *testing.T) {
	g := newFakeGateway(t)
	g.failResource = true
	svc, _, _ := newServiceWithFakeDialer(t, g)

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		t.Fatalf("Login 失败: %v", err)
	}

	waitFor(t, func() bool { return svc.GetStatus()["resourceState"] == string(ResourceError) })

	if !svc.IsActive() {
		t.Error("资源拉取失败后会话不应结束")
	}
	if svc.Client == nil {
		t.Error("资源拉取失败后 client 被清空了")
	}
	// 失败时不应留下半启动的代理。
	svc.mu.Lock()
	proxy := svc.proxy
	svc.mu.Unlock()
	if proxy != nil && proxy.ActiveListeners() != 0 {
		t.Error("资源拉取失败却建立了监听")
	}

	// 重试成功后应当恢复正常。
	g.failResource = false
	if _, err := svc.RefreshResources(); err != nil {
		t.Fatalf("重试失败: %v", err)
	}
	if st := svc.GetStatus(); st["resourceState"] != string(ResourceReady) {
		t.Errorf("重试后 resourceState = %v", st["resourceState"])
	}
}

// TestATrustConcurrentStatusDuringLoad 在资源加载期间高频读状态。
//
// 这是死锁最容易被触发的形态：UI 会定时轮询 GetStatus，而加载在另一个
// 协程里跑。用 -race 跑时还能顺带发现数据竞争。
func TestATrustConcurrentStatusDuringLoad(t *testing.T) {
	g := newFakeGateway(t)
	svc, _, _ := newServiceWithFakeDialer(t, g)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = svc.GetStatus()
				}
			}
		}()
	}

	if _, err := svc.Login("gw-atrust-test", "alice", "secret-pass", false, false); err != nil {
		close(stop)
		wg.Wait()
		t.Fatalf("Login 失败: %v", err)
	}
	waitFor(t, func() bool { return svc.GetStatus()["resourceState"] == string(ResourceReady) })
	close(stop)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("并发读状态时卡住了")
	}
}
