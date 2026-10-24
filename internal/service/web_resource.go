package service

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
	"github.com/hygkui/v5vpn-rea-client/internal/proxy"
)

// WebResource 描述一条「端口区间」资源及其本地 CONNECT 代理。
//
// 网关把堡垒机这类资源下发为 port="1-65535"：它覆盖全部端口，无法像单端口
// 资源那样映射到一个固定本地端口，因此改用本地 CONNECT 代理供浏览器访问。
type WebResource struct {
	Name       string `json:"name"`
	RemoteAddr string `json:"remoteAddr"`
	PortRange  string `json:"portRange"`
	MapID      string `json:"mapId"`
	ProxyAddr  string `json:"proxyAddr"`
}

// startWebResources 为端口区间类资源建立本地 CONNECT 代理。
// 返回的代理由调用方负责在会话结束或资源刷新时停止。
func (s *VPNService) startWebResources(client *protocol.Client, cert *tls.Certificate,
	resources []protocol.TCPUDPResource) ([]*proxy.WebProxy, []WebResource) {

	var proxies []*proxy.WebProxy
	var items []WebResource

	for _, r := range resources {
		if !strings.Contains(r.Port, "-") {
			continue
		}
		addr := strings.TrimSpace(r.Addr)
		if addr == "" && len(r.IPConfigs) > 0 {
			addr = strings.TrimSpace(strings.Split(r.IPConfigs[0].Addr, "-")[0])
		}
		if addr == "" || r.MapID == "" {
			s.Log("WARN", "网页资源 %q 缺少地址或 MapID，已跳过 (addr=%q mapid=%q)", r.Name, addr, r.MapID)
			continue
		}

		wp := proxy.NewWebProxy(client.GatewayIP, client.GatewayPort, client.SessionID, r.MapID, cert, s.Log)
		localAddr, err := wp.Start()
		if err != nil {
			s.Log("WARN", "网页资源 %q 启动本地代理失败: %v", r.Name, err)
			continue
		}
		proxies = append(proxies, wp)
		items = append(items, WebResource{
			Name:       r.Name,
			RemoteAddr: addr,
			PortRange:  r.Port,
			MapID:      r.MapID,
			ProxyAddr:  localAddr,
		})
		s.Log("SUCCESS", "网页资源就绪: %s -> %s（本地代理 %s）", r.Name, addr, localAddr)
	}
	return proxies, items
}

// OpenWebResource 用本地 CONNECT 代理启动浏览器访问网页类资源。
// proxyAddr 必须属于当前会话已启动的代理，避免被任意本地程序借用。
func (s *VPNService) OpenWebResource(rawURL, proxyAddr string) error {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(rawURL, "https://") && !strings.HasPrefix(rawURL, "http://") {
		return fmt.Errorf("请输入以 http:// 或 https:// 开头的地址")
	}

	s.mu.Lock()
	found := false
	for _, wp := range s.WebProxies {
		if wp.Addr() == proxyAddr {
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return fmt.Errorf("网页代理不可用，请重新登录后再试")
	}

	s.Log("INFO", "正在以代理模式打开 %s（代理 %s）", rawURL, proxyAddr)
	exe, err := launchBrowserWithProxy(rawURL, proxyAddr)
	if err != nil {
		return err
	}
	if exe != "" {
		s.Log("INFO", "浏览器: %s", exe)
	}
	return nil
}

// launchBrowserWithProxy 用独立的浏览器配置目录启动 Chromium 内核浏览器，
// 并指定本地 CONNECT 代理；独立目录保证即使用户已开着浏览器，新参数也能生效。
// 返回实际使用的浏览器路径（非 Windows 平台为空）。
func launchBrowserWithProxy(rawURL, proxyAddr string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		exe := findChromiumBrowser()
		if exe == "" {
			return "", fmt.Errorf("未找到可用的 Chromium 内核浏览器（Edge / Chrome / 360 / QQ 等）。" +
				"可设置环境变量 V5VPN_BROWSER 指向浏览器 exe 后重试")
		}
		profile := filepath.Join(browserProfileDir(), "browser-profile")
		if err := os.MkdirAll(profile, 0o700); err != nil {
			return "", fmt.Errorf("创建浏览器配置目录失败: %w", err)
		}
		args := []string{
			"--proxy-server=http://" + proxyAddr,
			"--proxy-bypass-list=" + localBypassList(),
			"--user-data-dir=" + profile,
			"--no-first-run",
			"--new-window",
			rawURL,
		}
		if err := exec.Command(exe, args...).Start(); err != nil {
			return "", fmt.Errorf("启动浏览器失败: %w", err)
		}
		return exe, nil
	case "darwin":
		return "", exec.Command("open", rawURL).Start()
	default:
		return "", exec.Command("xdg-open", rawURL).Start()
	}
}

// browserProfileDir 返回存放独立浏览器配置的目录（与 setting.xml 同级）。
func browserProfileDir() string {
	if dir := config.UserDataDir(); dir != "" {
		return dir
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "v5vpn-rea")
	}
	return os.TempDir()
}

// findChromiumBrowser 在常见安装路径中查找 Chromium 内核浏览器。
//
// 国内机器上 Edge/Chrome 往往不是默认浏览器，360 极速浏览器 X、RunningCheese、
// QQ、搜狗等同样基于 Chromium、支持 --proxy-server，因此一并纳入探测；
// 仍找不到时可用环境变量 V5VPN_BROWSER 手工指定 exe 路径。
func findChromiumBrowser() string {
	if custom := strings.TrimSpace(os.Getenv("V5VPN_BROWSER")); custom != "" {
		if info, err := os.Stat(custom); err == nil && !info.IsDir() {
			return custom
		}
	}

	var roots []string
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA", "APPDATA"} {
		if base := os.Getenv(env); base != "" {
			roots = append(roots, base)
		}
	}

	// 按优先级排列；带版本号的目录用通配符匹配，并优先取版本号较大的。
	patterns := []string{
		`Microsoft\Edge\Application\msedge.exe`,
		`Google\Chrome\Application\chrome.exe`,
		`360ChromeX-*\Application\360chromex.exe`,
		`360Chrome\Chrome\Application\360chrome.exe`,
		`360se6\Application\360se.exe`,
		`RunningCheeseChrome\App\chrome.exe`,
		`Tencent\QQBrowser\QQBrowser.exe`,
		`SogouExplorer\SogouExplorer.exe`,
		`Quark\QuarkBrowser.exe`,
		`BraveSoftware\Brave-Browser\Application\brave.exe`,
		`Vivaldi\Application\vivaldi.exe`,
	}

	for _, root := range roots {
		for _, pattern := range patterns {
			matches, _ := filepath.Glob(filepath.Join(root, pattern))
			if len(matches) == 0 {
				continue
			}
			sort.Sort(sort.Reverse(sort.StringSlice(matches)))
			for _, path := range matches {
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					return path
				}
			}
		}
	}
	return ""
}

// localBypassList 生成浏览器代理绕过列表：本机所在网段与回环地址直连，
// 避免把 NAS 等本地设备流量送进 VPN 隧道。
func localBypassList() string {
	parts := []string{"<local>", "127.0.0.1", "localhost"}
	seen := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipnet.IP.To4()
				if ip4 == nil || ip4.IsLoopback() {
					continue
				}
				prefix := fmt.Sprintf("%d.%d.%d.*", ip4[0], ip4[1], ip4[2])
				if !seen[prefix] {
					seen[prefix] = true
					parts = append(parts, prefix)
				}
			}
		}
	}
	return strings.Join(parts, ";")
}

// SetLocalPort 记录本地 HTTP 服务端口，用于生成系统 PAC 地址。
func (s *VPNService) SetLocalPort(port int) {
	s.mu.Lock()
	s.localPort = port
	s.mu.Unlock()
}

// PACScript 生成 PAC：只把网页类资源的目标地址交给本地 CONNECT 代理，
// 其余（NAS、外网、本机）一律直连。
func (s *VPNService) PACScript() string {
	s.mu.Lock()
	items := append([]WebResource(nil), s.WebResources...)
	extra := s.webProxyCfg.ExtraTargets
	s.mu.Unlock()

	// 额外地址沿用第一条网页资源的代理：一次会话里只有一条隧道路径。
	proxyAddr := ""
	for _, w := range items {
		if w.ProxyAddr != "" {
			proxyAddr = w.ProxyAddr
			break
		}
	}

	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")
	seen := map[string]bool{}
	for _, w := range items {
		if w.RemoteAddr == "" || w.ProxyAddr == "" || seen[w.RemoteAddr] {
			continue
		}
		seen[w.RemoteAddr] = true
		fmt.Fprintf(&b, "  if (host === \"%s\") return \"PROXY %s\";\n", w.RemoteAddr, w.ProxyAddr)
	}
	if proxyAddr != "" {
		for _, rule := range extraTargetRules(extra) {
			if seen[rule] {
				continue
			}
			seen[rule] = true
			if strings.Contains(rule, "*") {
				fmt.Fprintf(&b, "  if (shExpMatch(host, \"%s\")) return \"PROXY %s\";\n", rule, proxyAddr)
			} else {
				fmt.Fprintf(&b, "  if (host === \"%s\") return \"PROXY %s\";\n", rule, proxyAddr)
			}
		}
	}
	b.WriteString("  return \"DIRECT\";\n}\n")
	return b.String()
}

func (s *VPNService) pacURL() string {
	s.mu.Lock()
	port := s.localPort
	s.mu.Unlock()
	if port <= 0 {
		return ""
	}
	return fmt.Sprintf("http://127.0.0.1:%d/proxy.pac", port)
}

// syncSystemPAC 在资源就绪后按用户设置启用系统 PAC；关闭或无网页资源时还原。
func (s *VPNService) syncSystemPAC(hasWebResource bool) {
	s.mu.Lock()
	enabled := s.webProxyCfg.PACEnabled
	s.mu.Unlock()

	if !enabled || !hasWebResource {
		s.disableSystemPAC()
		return
	}
	s.applySystemPACNow()
}

func (s *VPNService) applySystemPACNow() {
	url := s.pacURL()
	if url == "" {
		s.Log("WARN", "本地服务端口未知，跳过系统 PAC 设置")
		return
	}
	if err := applySystemPAC(url); err != nil {
		s.Log("WARN", "启用系统 PAC 失败: %v", err)
		return
	}
	s.Log("SUCCESS", "已启用系统 PAC：%s（仅列表内地址走代理，其余直连；断开后自动还原）", url)
}

// disableSystemPAC 还原被本客户端改过的系统代理设置。
func (s *VPNService) disableSystemPAC() {
	restored, err := restoreSystemProxy()
	if err != nil {
		s.Log("WARN", "还原系统代理失败: %v", err)
		return
	}
	if restored {
		s.Log("INFO", "系统代理设置已还原")
	}
}
