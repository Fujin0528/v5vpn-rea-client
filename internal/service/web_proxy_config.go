package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// webProxyConfig 是网页资源代理的用户设置，持久化在用户数据目录。
//   - PACEnabled：是否接管系统 PAC（让本机所有浏览器都能访问内网资源）
//   - ExtraTargets：额外代理地址，支持精确 IP/主机名与通配（10.10.20.*）
type webProxyConfig struct {
	PACEnabled   bool   `json:"pacEnabled"`
	ExtraTargets string `json:"extraTargets"`
}

func defaultWebProxyConfig() webProxyConfig {
	return webProxyConfig{PACEnabled: true}
}

func webProxyConfigPath() string {
	dir := browserProfileDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "webproxy-config.json")
}

func loadWebProxyConfig() webProxyConfig {
	cfg := defaultWebProxyConfig()
	path := webProxyConfigPath()
	if path == "" {
		return cfg
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(data, &cfg)
	return cfg
}

func (cfg webProxyConfig) save() error {
	path := webProxyConfigPath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// GetWebProxyConfig 返回当前网页代理设置（供前端回显）。
func (s *VPNService) GetWebProxyConfig() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"pacEnabled":   s.webProxyCfg.PACEnabled,
		"extraTargets": s.webProxyCfg.ExtraTargets,
	}
}

// SetWebProxyConfig 保存设置并立即生效：开启则应用 PAC，关闭则还原系统代理。
func (s *VPNService) SetWebProxyConfig(pacEnabled bool, extraTargets string) error {
	cfg := webProxyConfig{
		PACEnabled:   pacEnabled,
		ExtraTargets: strings.TrimSpace(extraTargets),
	}

	s.mu.Lock()
	s.webProxyCfg = cfg
	hasWeb := len(s.WebResources) > 0
	s.mu.Unlock()

	if err := cfg.save(); err != nil {
		return fmt.Errorf("保存网页代理设置失败: %w", err)
	}
	if pacEnabled && hasWeb {
		s.applySystemPACNow()
	} else {
		s.disableSystemPAC()
	}
	return nil
}

// extraTargetRules 把用户输入的额外地址转成 PAC 匹配规则。
// 支持：精确地址（10.10.20.15）、通配（10.10.20.*）、
// 以及 /8 /16 /24 形式的网段（转成通配形式）。
func extraTargetRules(extra string) []string {
	var rules []string
	for _, raw := range strings.FieldsFunc(extra, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == ' ' || r == '\t'
	}) {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		if strings.Contains(target, "/") {
			parts := strings.SplitN(target, "/", 2)
			ip := parts[0]
			octets := strings.Split(ip, ".")
			if len(octets) != 4 {
				continue
			}
			switch parts[1] {
			case "8":
				target = octets[0] + ".*"
			case "16":
				target = octets[0] + "." + octets[1] + ".*"
			case "24":
				target = octets[0] + "." + octets[1] + "." + octets[2] + ".*"
			default:
				continue
			}
		}
		rules = append(rules, target)
	}
	return rules
}
