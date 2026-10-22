package main

// backends_test.go — 双后端的活动判定与失败隔离。
//
// 边界三说「aTrust 侧的失败不得触发 V5VPN 的 Logout」。这条边界最容易
// 在"退出钩子无条件调用 vpnService.Logout()"这种写法上失守，
// 所以这里直接验 backends.logoutActive() 的分支。
//
// 测试用的是假后端而不是真实服务：真实服务要做到"已连接"状态必须真连上
// 一个网关，那会把一个关于分支的单元测试变成集成测试；而这里想验的
// 恰恰只是「按状态字符串决定调谁」，与协议实现无关。

import (
	"sync"
	"testing"
)

// fakeBackend 记录 Logout 是否被调用，用来断言"没被碰过"。
type fakeBackend struct {
	mu          sync.Mutex
	status      string
	logoutCalls int
	logoutErr   error
}

func (f *fakeBackend) GetStatus() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]any{"status": f.status}
}

func (f *fakeBackend) Logout() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logoutCalls++
	f.status = "Disconnected"
	return true, f.logoutErr
}

func (f *fakeBackend) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logoutCalls
}

func newTestBackends(v5Status, atStatus string) (*backends, *fakeBackend, *fakeBackend) {
	v5 := &fakeBackend{status: v5Status}
	at := &fakeBackend{status: atStatus}
	return &backends{v5vpn: v5, atrust: at}, v5, at
}

// TestBackendsActiveNone 验证两个后端都空闲时的判定。
func TestBackendsActiveNone(t *testing.T) {
	b, _, _ := newTestBackends("Disconnected", "Disconnected")
	if got := b.active(); got != "" {
		t.Fatalf("active() = %q，期望空", got)
	}
}

// TestBackendsActiveV5VPN 验证 V5VPN 会话被正确识别。
func TestBackendsActiveV5VPN(t *testing.T) {
	for _, status := range []string{"Connected", "Connecting"} {
		b, _, _ := newTestBackends(status, "Disconnected")
		if got := b.active(); got != "v5vpn" {
			t.Errorf("V5VPN=%s 时 active() = %q，期望 v5vpn", status, got)
		}
	}

	// Error 不算活动：连接已失败，没有会话需要登出。
	b, _, _ := newTestBackends("Error", "Disconnected")
	if got := b.active(); got != "" {
		t.Errorf("V5VPN=Error 时 active() = %q，期望空", got)
	}
}

// TestBackendsActiveATrust 验证 aTrust 会话被正确识别。
func TestBackendsActiveATrust(t *testing.T) {
	b, _, _ := newTestBackends("Disconnected", "Connected")
	if got := b.active(); got != "atrust" {
		t.Fatalf("active() = %q，期望 atrust", got)
	}
}

// TestBackendsActiveBoth 验证两个后端同时有会话时的判定。
//
// 这不该发生（登录会拆旧会话），但真发生时要能被识别，
// 否则退出流程会漏掉一个会话。
func TestBackendsActiveBoth(t *testing.T) {
	b, _, _ := newTestBackends("Connected", "Connected")
	if got := b.active(); got != "both" {
		t.Fatalf("active() = %q，期望 both", got)
	}
}

// TestLogoutActiveLeavesIdleBackendsAlone 是边界三的核心断言：
// 两个都空闲时，任何 Logout 都不能被调用。
func TestLogoutActiveLeavesIdleBackendsAlone(t *testing.T) {
	b, v5, at := newTestBackends("Disconnected", "Disconnected")
	b.logoutActive()

	if v5.calls() != 0 {
		t.Errorf("空闲时 V5VPN.Logout 被调用 %d 次", v5.calls())
	}
	if at.calls() != 0 {
		t.Errorf("空闲时 aTrust.Logout 被调用 %d 次", at.calls())
	}
}

// TestLogoutActiveClosesOnlyV5VPN 验证只关有会话的那一个。
func TestLogoutActiveClosesOnlyV5VPN(t *testing.T) {
	b, v5, at := newTestBackends("Connected", "Disconnected")
	b.logoutActive()

	if v5.calls() != 1 {
		t.Errorf("V5VPN.Logout 调用 %d 次，期望 1", v5.calls())
	}
	if at.calls() != 0 {
		t.Errorf("aTrust.Logout 不应被调用，实际 %d 次", at.calls())
	}
}

// TestLogoutActiveClosesOnlyATrust 验证 aTrust 活动时不去碰 V5VPN。
//
// 这是最容易写错的方向：退出钩子原来无条件调 vpnService.Logout()，
// 会在 V5VPN 的日志里留下一条 Tearing down，看起来像 V5VPN 掉线了。
func TestLogoutActiveClosesOnlyATrust(t *testing.T) {
	b, v5, at := newTestBackends("Disconnected", "Connected")
	b.logoutActive()

	if v5.calls() != 0 {
		t.Errorf("aTrust 活动时 V5VPN.Logout 被调用 %d 次，期望 0", v5.calls())
	}
	if at.calls() != 1 {
		t.Errorf("aTrust.Logout 调用 %d 次，期望 1", at.calls())
	}
}

// TestLogoutActiveClosesBoth 验证异常状态下的兜底。
func TestLogoutActiveClosesBoth(t *testing.T) {
	b, v5, at := newTestBackends("Connected", "Connecting")
	b.logoutActive()

	if v5.calls() != 1 || at.calls() != 1 {
		t.Errorf("期望两边各一次: v5=%d at=%d", v5.calls(), at.calls())
	}
}

// TestLogoutActiveSurvivesOneFailure 验证一个后端的登出失败不影响另一个。
func TestLogoutActiveSurvivesOneFailure(t *testing.T) {
	v5 := &fakeBackend{status: "Connected", logoutErr: errStub{}}
	at := &fakeBackend{status: "Connected"}
	b := &backends{v5vpn: v5, atrust: at}

	b.logoutActive()

	if at.calls() != 1 {
		t.Errorf("V5VPN 登出失败后 aTrust 仍应被登出，实际 %d 次", at.calls())
	}
}

// TestBackendsNilSafety 验证某个后端缺位时不会 panic。
//
// 打包阶段的构建（例如只带 V5VPN 的变体）可能不注册 aTrust。
func TestBackendsNilSafety(t *testing.T) {
	b := &backends{}
	if got := b.active(); got != "" {
		t.Errorf("全 nil 时 active() = %q", got)
	}
	b.logoutActive() // 不应 panic

	onlyV5 := &backends{v5vpn: &fakeBackend{status: "Connected"}}
	if got := onlyV5.active(); got != "v5vpn" {
		t.Errorf("只注册 V5VPN 时 active() = %q", got)
	}
}

type errStub struct{}

func (errStub) Error() string { return "stub failure" }
