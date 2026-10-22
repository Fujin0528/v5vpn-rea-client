package config

// protocol_test.go — 验证新增的 Protocol 字段不会影响既有的 setting.xml。
//
// 这是 §14.5.4 验收清单的第一条：旧配置文件必须能直接加载，
// 且 Protocol 的零值必须被当作 V5VPN，不需要任何迁移。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGatewayProfileMissingProtocol 反序列化一个不含 protocol 的网关条目，
// 断言零值语义正确。这是升级路径的关键：老用户不会改配置。
func TestGatewayProfileMissingProtocol(t *testing.T) {
	// 这是升级前版本写出的 JSON 形状。
	const old = `{
		"id": "gw-legacy",
		"name": "老网关",
		"ip": "192.0.2.10",
		"port": 443,
		"algo": 0,
		"lastUserName": "alice",
		"authType": 0,
		"certType": 0,
		"certAutoLogin": false,
		"selectedCertId": "",
		"savedAccounts": [{"username": "alice", "password": "x", "remember": true, "auto": false}]
	}`

	var gw GatewayProfile
	if err := json.Unmarshal([]byte(old), &gw); err != nil {
		t.Fatalf("旧配置反序列化失败: %v", err)
	}

	if gw.Protocol != "" {
		t.Fatalf("Protocol 零值应为空串，实际 %q", gw.Protocol)
	}
	if got := gw.EffectiveProtocol(); got != ProtocolV5VPN {
		t.Fatalf("EffectiveProtocol() = %q, 期望 %q", got, ProtocolV5VPN)
	}
	if gw.IsATrust() {
		t.Fatal("旧配置不应被识别为 aTrust")
	}

	// 既有字段一个都不能丢。
	if gw.ID != "gw-legacy" || gw.IP != "192.0.2.10" || gw.Port != 443 {
		t.Fatalf("既有字段被破坏: %+v", gw)
	}
	if len(gw.SavedAccounts) != 1 || gw.SavedAccounts[0].Username != "alice" {
		t.Fatalf("账号列表被破坏: %+v", gw.SavedAccounts)
	}
}

// TestGatewayProfileATrustRoundTrip 验证 aTrust 网关的序列化往返。
func TestGatewayProfileATrustRoundTrip(t *testing.T) {
	gw := GatewayProfile{
		ID:       "gw-atrust",
		Name:     "办公网关",
		IP:       "198.51.100.20",
		Port:     443,
		Protocol: ProtocolATrust,
	}

	buf, err := json.Marshal(gw)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}

	var back GatewayProfile
	if err := json.Unmarshal(buf, &back); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if !back.IsATrust() {
		t.Fatalf("往返后 IsATrust() = false，JSON: %s", buf)
	}
	if back.EffectiveProtocol() != ProtocolATrust {
		t.Fatalf("EffectiveProtocol() = %q", back.EffectiveProtocol())
	}
}

// TestProtocolOmittedWhenV5VPN 验证 ProtocolV5VPN 的显式值也会被写入，
// 但不含 protocol 的旧数据仍然空着——两者等价但形状不同。
//
// 这里不强制 omitempty 的行为，只确认读回来是等价的。
func TestProtocolOmittedWhenV5VPN(t *testing.T) {
	gw := GatewayProfile{ID: "gw", Protocol: ProtocolV5VPN}
	buf, err := json.Marshal(gw)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var back GatewayProfile
	if err := json.Unmarshal(buf, &back); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if back.IsATrust() {
		t.Fatal("ProtocolV5VPN 不应被识别为 aTrust")
	}
}

// TestEffectiveProtocolUnknownFallsBackToV5VPN 守护一个安全默认：
// 任何未知的 protocol 值都退回 V5VPN，而不是让网关变成不可用。
func TestEffectiveProtocolUnknownFallsBackToV5VPN(t *testing.T) {
	for _, v := range []string{"", "v5vpn", "V5VPN", "atrust-typo", "unknown"} {
		gw := GatewayProfile{Protocol: v}
		if gw.IsATrust() {
			t.Errorf("Protocol=%q 不应被识别为 aTrust", v)
		}
		if gw.EffectiveProtocol() != ProtocolV5VPN {
			t.Errorf("Protocol=%q 的 EffectiveProtocol 应为 v5vpn，实际 %q", v, gw.EffectiveProtocol())
		}
	}
}

// TestProtocolPersistsThroughSettingXML 是 v0.3.0 之前的一个真实缺陷的回归。
//
// Protocol 最初只加在 JSON tag 上，而 setting.xml 的读写走的是独立的
// XML 结构体（GatewayXML）。结果是：用户在界面上添加一个 aTrust 网关，
// 内存里是对的，重启后 protocol 属性根本没被写过，网关静默退回 V5VPN，
// 表现为「明明加了零信任网关，重启后它变成了普通 VPN 网关」。
//
// 这个测试同时锁定两件事：
//   - aTrust 网关的 protocol 能存进 setting.xml 并读回来
//   - V5VPN 网关不写 protocol 属性（保持原客户端可读）
func TestProtocolPersistsThroughSettingXML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setting.xml")

	cfg := &AppConfig{Gateways: []GatewayProfile{
		{ID: "gw-0", Name: "老网关", IP: "192.0.2.10", Port: 443},
		{ID: "gw-1", Name: "办公网关", IP: "198.51.100.20", Port: 443, Protocol: ProtocolATrust},
	}}
	if err := cfg.SaveSettingXML(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, `protocol="atrust"`) {
		t.Fatalf("aTrust 网关的 protocol 未写入 XML:\n%s", content)
	}
	// V5VPN 网关不应带 protocol 属性，否则原客户端会看到一个陌生字段。
	if strings.Count(content, "protocol=") != 1 {
		t.Fatalf("只有 aTrust 网关应带 protocol 属性，实际出现 %d 次:\n%s",
			strings.Count(content, "protocol="), content)
	}

	back, err := LoadSettingXML(path)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	if len(back.Gateways) != 2 {
		t.Fatalf("网关数 = %d", len(back.Gateways))
	}
	if back.Gateways[0].IsATrust() {
		t.Error("老网关在往返后变成了 aTrust")
	}
	if !back.Gateways[1].IsATrust() {
		t.Error("aTrust 网关在往返后退回了 V5VPN —— 这正是本测试要防的缺陷")
	}
}
