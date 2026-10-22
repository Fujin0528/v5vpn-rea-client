package main

// ui_routes_test.go — 启动时先打开哪一套界面。
//
// 两套前端物理分开后，窗口只有一个根入口，这条选择规则就成了一条
// 必须被测试拴住的契约：判错协议 = 用户重启后站在一套连不上的界面上。
// 这里的每个分支都对应一种真实的 setting.xml 形态。

import (
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
)

func TestInitialUIPath(t *testing.T) {
	atrustGW := config.GatewayProfile{
		ID: "gw-1", Name: "办公零信任", IP: "198.51.100.20", Port: 443,
		Protocol: config.ProtocolATrust,
	}
	v5GW := config.GatewayProfile{ID: "gw-0", Name: "老网关", IP: "192.0.2.10", Port: 443}
	// 显式写了 v5vpn 的网关：Protocol 非空但不是 atrust，仍归 V5VPN。
	explicitV5GW := config.GatewayProfile{
		ID: "gw-2", Name: "新 V5VPN", IP: "192.0.2.11", Port: 443,
		Protocol: config.ProtocolV5VPN,
	}

	cfg := &config.AppConfig{
		Gateways:       []config.GatewayProfile{v5GW, atrustGW, explicitV5GW},
		LastUseGateway: "",
	}

	cases := []struct {
		name     string
		lastUse  string
		wantPath string
	}{
		{"无记录默认 V5VPN", "", uiPathV5VPN},
		{"上次用 aTrust 网关", "办公零信任", uiPathATrust},
		{"上次用老网关", "老网关", uiPathV5VPN},
		{"上次用显式 v5vpn 网关", "新 V5VPN", uiPathV5VPN},
		// FindGateway 同时支持按 ID / IP 匹配，启动路由要继承同一套匹配。
		{"按 ID 命中 aTrust 网关", "gw-1", uiPathATrust},
		{"按 IP 命中 aTrust 网关", "198.51.100.20", uiPathATrust},
		// 记录指向已删除的网关：按 V5VPN 兜底，而不是把用户送进
		// 一套可能从没用过的 aTrust 界面。
		{"网关已删除", "不存在的网关", uiPathV5VPN},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg.LastUseGateway = c.lastUse
			if got := initialUIPath(cfg); got != c.wantPath {
				t.Fatalf("initialUIPath(lastUse=%q) = %q，期望 %q", c.lastUse, got, c.wantPath)
			}
		})
	}
}

// TestInitialUIPathNilConfig 守护启动早期配置尚未加载的路径：这里必须
// 返回默认界面而不是 panic，否则窗口永远打不开。
func TestInitialUIPathNilConfig(t *testing.T) {
	if got := initialUIPath(nil); got != uiPathV5VPN {
		t.Fatalf("initialUIPath(nil) = %q，期望 %q", got, uiPathV5VPN)
	}
}

// TestInitialUIPathEmptyConfig 覆盖 setting.xml 全新（没有任何网关）的
// 首次启动：默认落在 V5VPN 界面。
func TestInitialUIPathEmptyConfig(t *testing.T) {
	if got := initialUIPath(&config.AppConfig{}); got != uiPathV5VPN {
		t.Fatalf("空配置 = %q，期望 %q", got, uiPathV5VPN)
	}
}

// TestUIPathsAreAbsolute 防止改成相对路径：窗口 URL 是
// http://127.0.0.1:<port> + 该路径，根重定向的 Location 也直接用它。
func TestUIPathsAreAbsolute(t *testing.T) {
	for _, p := range []string{uiPathV5VPN, uiPathATrust} {
		if len(p) < 2 || p[0] != '/' || p[len(p)-1] != '/' {
			t.Errorf("界面路径 %q 必须以 / 开头并以 / 结尾", p)
		}
	}
}
