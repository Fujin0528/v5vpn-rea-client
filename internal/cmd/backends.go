package main

// backends.go — 把两个协议后端放在一起。
//
// 存在的理由只有一个：托盘菜单与退出钩子需要"当前激活的是哪个后端"这个
// 全局视角，而两个服务彼此不知道对方。让它们互相引用会造出一条
// service 包内部的环（§14.5.2 边界二），所以这个判断放在 cmd 层。
//
// ⚠ 这里刻意只做"查询与关停"，不做登录路由。登录走各自的 endpoint，
// UI 按 gateway.protocol 选择——路由判断散在两层很容易出现
// "界面以为在连 aTrust、实际打到了 V5VPN" 的分裂。

import (
	"log"

	"github.com/hygkui/v5vpn-rea-client/internal/service"
)

// sessionBackend 是两个后端共有的最小能力。
//
// 用接口而不是 *service.VPNService / *service.ATrustService：
//   - 测试可以注入假后端，不必构造完整服务或伪造连接状态
//   - 生产代码无法在这里调用登录、代理、证书等能力，
//     边界二（服务级隔离）因此在类型层面就成立了
type sessionBackend interface {
	GetStatus() map[string]any
	Logout() (bool, error)
}

// backends 持有两个后端并回答"谁在活动"。
type backends struct {
	v5vpn  sessionBackend
	atrust sessionBackend
}

// active 返回当前有会话的后端名（"v5vpn" / "atrust"），都没有时返回 ""。
//
// 两个都活动是可能的：用户先用 V5VPN 连上一台网关，再从设置里切到一台
// aTrust 网关登录。这种情况下登录方本身应当先拆掉旧会话；若没拆干净，
// 这里返回 "both"，让调用方两边都关。
func (b *backends) active() string {
	v5 := b.v5vpnActive()
	at := b.atrustActive()
	switch {
	case v5 && at:
		return "both"
	case v5:
		return "v5vpn"
	case at:
		return "atrust"
	default:
		return ""
	}
}

// v5vpnActive 从公共状态接口判断 V5VPN 是否有会话。
//
// 用 GetStatus 而不是给 VPNService 加 IsActive：边界二要求不动它的
// 方法集合，而状态字符串本来就是它对外承诺的一部分。
func (b *backends) v5vpnActive() bool {
	if b.v5vpn == nil {
		return false
	}
	return isSessionActive(b.v5vpn)
}

func (b *backends) atrustActive() bool {
	if b.atrust == nil {
		return false
	}
	return isSessionActive(b.atrust)
}

// isSessionActive 按状态字符串判断会话是否处于活动期。
//
// 两个后端的状态取值是同一套（Disconnected / Connecting / Connected /
// Error），所以判定逻辑可以共用；「Error」不算活动——连接已失败，
// 没有会话需要登出。
func isSessionActive(backend sessionBackend) bool {
	status, _ := backend.GetStatus()["status"].(string)
	return status == "Connecting" || status == "Connected"
}

// logoutActive 只登出有会话的后端。
//
// 这是边界三的落点：aTrust 未连接时，退出流程不应在 V5VPN 的日志里
// 写一条 "Tearing down VPN session"。反过来也一样。
func (b *backends) logoutActive() {
	switch b.active() {
	case "v5vpn":
		b.logoutOne(b.v5vpn, "V5VPN")
	case "atrust":
		b.logoutOne(b.atrust, "aTrust")
	case "both":
		// 两个都关，且各自失败不影响另一个。
		b.logoutOne(b.v5vpn, "V5VPN")
		b.logoutOne(b.atrust, "aTrust")
	}
}

func (b *backends) logoutOne(backend sessionBackend, label string) {
	if backend == nil {
		return
	}
	if _, err := backend.Logout(); err != nil {
		log.Printf("%s logout error (ignored): %v", label, err)
	}
}

// 编译期断言：两个真实后端都满足接口。
var (
	_ sessionBackend = (*service.VPNService)(nil)
	_ sessionBackend = (*service.ATrustService)(nil)
)
