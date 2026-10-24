//go:build windows

package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// 系统 PAC 模式：把 Windows 的「自动配置脚本」(AutoConfigURL) 指向本机
// /proxy.pac，只让网页类资源的目标地址走本地代理，其余一律直连。
// 这样用户自己已经打开的浏览器（360 / Edge / Chrome）无需带启动参数也能访问
// 堡垒机，同时 NAS、外网都不受影响。
const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type proxyBackup struct {
	HadAutoConfig  bool   `json:"hadAutoConfig"`
	AutoConfigURL  string `json:"autoConfigUrl"`
	HadProxyEnable bool   `json:"hadProxyEnable"`
	ProxyEnable    uint32 `json:"proxyEnable"`
	HadProxyServer bool   `json:"hadProxyServer"`
	ProxyServer    string `json:"proxyServer"`
}

func proxyBackupPath() string {
	if dir := browserProfileDir(); dir != "" {
		return filepath.Join(dir, "system-proxy-backup.json")
	}
	return ""
}

// applySystemPAC 备份当前代理设置并写入 AutoConfigURL。
func applySystemPAC(pacURL string) error {
	if pacURL == "" {
		return fmt.Errorf("PAC 地址为空")
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开 Internet 设置失败: %w", err)
	}
	defer key.Close()

	// 已有备份说明是本客户端设置的 PAC（例如资源刷新后再次应用），
	// 此时只更新指向的 PAC 地址，绝不能用当前值覆盖原始设置。
	if path := proxyBackupPath(); path != "" {
		if _, err := os.Stat(path); err == nil {
			if err := key.SetStringValue("AutoConfigURL", pacURL); err != nil {
				return fmt.Errorf("更新 AutoConfigURL 失败: %w", err)
			}
			notifyProxyChanged()
			return nil
		}
	}

	backup := proxyBackup{}
	if v, _, err := key.GetStringValue("AutoConfigURL"); err == nil {
		backup.HadAutoConfig = true
		backup.AutoConfigURL = v
	}
	if v, _, err := key.GetIntegerValue("ProxyEnable"); err == nil {
		backup.HadProxyEnable = true
		backup.ProxyEnable = uint32(v)
	}
	if v, _, err := key.GetStringValue("ProxyServer"); err == nil {
		backup.HadProxyServer = true
		backup.ProxyServer = v
	}

	if path := proxyBackupPath(); path != "" {
		if data, err := json.MarshalIndent(backup, "", "  "); err == nil {
			_ = os.WriteFile(path, data, 0o600)
		}
	}

	if err := key.SetStringValue("AutoConfigURL", pacURL); err != nil {
		return fmt.Errorf("写入 AutoConfigURL 失败: %w", err)
	}
	notifyProxyChanged()
	return nil
}

// restoreSystemProxy 按备份还原系统代理设置，并删除备份文件。
// 返回是否确实做了还原（没有备份时返回 false）。
func restoreSystemProxy() (bool, error) {
	path := proxyBackupPath()
	if path == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil // 没有备份：本客户端没有改过系统设置
	}
	var backup proxyBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		_ = os.Remove(path)
		return false, nil
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return false, fmt.Errorf("打开 Internet 设置失败: %w", err)
	}
	defer key.Close()

	if backup.HadAutoConfig {
		_ = key.SetStringValue("AutoConfigURL", backup.AutoConfigURL)
	} else {
		_ = key.DeleteValue("AutoConfigURL")
	}
	if backup.HadProxyEnable {
		_ = key.SetDWordValue("ProxyEnable", backup.ProxyEnable)
	}
	if backup.HadProxyServer {
		_ = key.SetStringValue("ProxyServer", backup.ProxyServer)
	}

	notifyProxyChanged()
	_ = os.Remove(path)
	return true, nil
}

// recoverSystemProxy 在启动时检查是否有上次异常退出遗留的备份并还原。
// 进程被强杀时还原不会执行，这一层保证下次启动能自动收拾干净。
func recoverSystemProxy() {
	path := proxyBackupPath()
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err == nil {
		_, _ = restoreSystemProxy()
	}
}

// notifyProxyChanged 通知 WinINET 代理设置已变更，让已运行的浏览器重新读取。
func notifyProxyChanged() {
	wininet := syscall.NewLazyDLL("wininet.dll")
	setOption := wininet.NewProc("InternetSetOptionW")
	const (
		internetOptionSettingsChanged = 39
		internetOptionRefresh         = 37
	)
	_, _, _ = setOption.Call(0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = setOption.Call(0, internetOptionRefresh, 0, 0)
}
