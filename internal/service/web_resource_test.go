package service

import (
	"strings"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// TestStartWebResourcesSelectsPortRangeOnly 验证只有端口区间（含 -）资源
// 会建本地 CONNECT 代理，以及地址解析的 addr 属性 → TCPUDP_IP 回退链。
func TestStartWebResourcesSelectsPortRangeOnly(t *testing.T) {
	s := &VPNService{}
	client := protocol.NewClient("127.0.0.1", 1, 0, nil)

	resources := []protocol.TCPUDPResource{
		{Name: "堡垒机", MapID: "M_100", Port: "1-65535", Addr: "10.10.20.15"},
		{Name: "单端口资源", MapID: "M_200", Port: "443", Addr: "10.0.0.9"},
		{Name: "仅子节点", MapID: "M_300", Port: "1-65535", IPConfigs: []protocol.TCPUDPIp{{Addr: "10.1.1.1-10.1.1.5"}}},
		{Name: "缺 mapid", MapID: "", Port: "1-65535", Addr: "10.2.2.2"},
		{Name: "缺地址", MapID: "M_500", Port: "1-65535"},
	}

	proxies, items := s.startWebResources(client, nil, resources)
	defer func() {
		for _, wp := range proxies {
			wp.Stop()
		}
	}()

	if len(proxies) != 2 || len(items) != 2 {
		t.Fatalf("got %d proxies / %d items, want 2/2 (items: %+v)", len(proxies), len(items), items)
	}

	first, second := items[0], items[1]
	if first.Name != "堡垒机" || first.RemoteAddr != "10.10.20.15" || first.PortRange != "1-65535" {
		t.Errorf("first item = %+v", first)
	}
	if first.MapID != "M_100" || first.ProxyAddr == "" || !strings.HasPrefix(first.ProxyAddr, "127.0.0.1:") {
		t.Errorf("first item mapID/proxyAddr = %q / %q", first.MapID, first.ProxyAddr)
	}
	// 子节点形态：地址在 TCPUDP_IP 上且带区间尾巴，取 - 前段。
	if second.RemoteAddr != "10.1.1.1" {
		t.Errorf("second item RemoteAddr = %q, want 10.1.1.1 (split from 10.1.1.1-10.1.1.5)", second.RemoteAddr)
	}
}

// TestPACScriptSkipsHostileTokens 守卫 PAC 注入面：资源地址与用户补充地址
// 都会被拼进 PAC 的 JS 字符串字面量，含引号/括号等字符的条目必须被丢弃，
// 而不是原样嵌入（PAC 是每次浏览器请求都会执行的脚本）。
func TestPACScriptSkipsHostileTokens(t *testing.T) {
	s := &VPNService{
		WebResources: []WebResource{
			{Name: "正常资源", RemoteAddr: "10.10.20.15", PortRange: "1-65535", ProxyAddr: "127.0.0.1:59761"},
			{Name: "恶意资源", RemoteAddr: `bad") alert(1); ("`, PortRange: "1-65535", ProxyAddr: "127.0.0.1:59761"},
			{Name: "带分号", RemoteAddr: "10.10.20.16;x", PortRange: "1-65535", ProxyAddr: "127.0.0.1:59761"},
		},
	}
	s.webProxyCfg = webProxyConfig{
		PACEnabled:   true,
		ExtraTargets: `ok-host.example, 10.10.30.*, evil")evil(1);("`,
	}

	pac := s.PACScript()

	if !strings.Contains(pac, `host === "10.10.20.15"`) {
		t.Errorf("PAC missing legitimate resource rule:\n%s", pac)
	}
	if !strings.Contains(pac, `host === "ok-host.example"`) {
		t.Errorf("PAC missing legitimate extra target:\n%s", pac)
	}
	if !strings.Contains(pac, `shExpMatch(host, "10.10.30.*")`) {
		t.Errorf("PAC missing wildcard extra target:\n%s", pac)
	}

	for _, banned := range []string{"alert(1)", "evil(1)", "10.10.20.16;x"} {
		if strings.Contains(pac, banned) {
			t.Errorf("PAC contains hostile token %q:\n%s", banned, pac)
		}
	}

	// 除丢弃的条目外结构完好：结尾仍是 DIRECT。
	if !strings.Contains(pac, `return "DIRECT";`) {
		t.Errorf("PAC missing DIRECT fallback:\n%s", pac)
	}
}

// TestPACScriptAcceptsIPv4AndHostTokens 锁定白名单的合法形态：
// IP、主机名、通配与连字符都应通过。
func TestPACScriptAcceptsIPv4AndHostTokens(t *testing.T) {
	for _, ok := range []string{"10.10.20.15", "intranet.corp.local", "10.10.*", "web-01.internal"} {
		if !pacSafeToken(ok) {
			t.Errorf("pacSafeToken(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", `x"`, "x;y", "x(y)", "x y", "x\ny", "::1", "x/y", "x'y"} {
		if pacSafeToken(bad) {
			t.Errorf("pacSafeToken(%q) = true, want false", bad)
		}
	}
}
