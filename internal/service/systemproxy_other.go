//go:build !windows

package service

import "fmt"

// 系统 PAC 模式目前只实现 Windows（WinINET）路径。
func applySystemPAC(string) error {
	return fmt.Errorf("系统 PAC 模式暂仅支持 Windows")
}

func restoreSystemProxy() (bool, error) { return false, nil }

func recoverSystemProxy() {}
