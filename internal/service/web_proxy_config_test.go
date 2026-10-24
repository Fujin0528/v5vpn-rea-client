package service

import (
	"strings"
	"testing"
)

func TestExtraTargetRules(t *testing.T) {
	rules := extraTargetRules("10.10.20.*, 10.1.2.0/24 10.0.0.0/8, bad/25, 10.10.20.15")
	want := []string{"10.10.20.*", "10.1.2.*", "10.*", "10.10.20.15"}
	if len(rules) != len(want) {
		t.Fatalf("rules = %v, want %v", rules, want)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Fatalf("rules[%d] = %q, want %q (all: %v)", i, rules[i], want[i], rules)
		}
	}
}

func TestPACScriptIncludesResourceAndExtraRules(t *testing.T) {
	s := &VPNService{
		WebResources: []WebResource{{
			Name:       "堡垒机",
			RemoteAddr: "10.10.20.15",
			PortRange:  "1-65535",
			ProxyAddr:  "127.0.0.1:59761",
		}},
	}
	s.webProxyCfg = webProxyConfig{
		PACEnabled:   true,
		ExtraTargets: "10.10.20.*, 10.1.2.0/24",
	}

	pac := s.PACScript()
	for _, want := range []string{
		`host === "10.10.20.15"`,
		`shExpMatch(host, "10.10.20.*")`,
		`shExpMatch(host, "10.1.2.*")`,
		`return "DIRECT";`,
		"PROXY 127.0.0.1:59761",
	} {
		if !strings.Contains(pac, want) {
			t.Fatalf("PAC missing %q:\n%s", want, pac)
		}
	}
}
