package atrust

// boundary_test.go — 守护 §14.5.2 的包级隔离硬边界。
//
// 规则：internal/atrust/** 不得 import internal/protocol 或 internal/proxy。
// 反过来（V5VPN 侧 import atrust）同样不允许。
//
// 这条测试用 go list 读真实的 import 图，而不是 grep 源码——
// grep 会漏掉别名导入、条件编译里的导入，而 go list 拿的是编译器的视图。

import (
	"os/exec"
	"strings"
	"testing"
)

// forbidden 是 aTrust 包不允许依赖的包（按导入路径后缀匹配）。
var forbidden = []string{
	"github.com/hygkui/v5vpn-rea-client/internal/protocol",
	"github.com/hygkui/v5vpn-rea-client/internal/proxy",
}

func TestPackageBoundary(t *testing.T) {
	modPath, err := modulePath()
	if err != nil {
		t.Skipf("无法取得模块路径（需要 go 工具链）: %v", err)
	}

	deps, err := listDeps(modPath + "/internal/atrust")
	if err != nil {
		t.Skipf("go list 不可用: %v", err)
	}

	for _, dep := range deps {
		for _, bad := range forbidden {
			if dep == bad {
				t.Errorf("internal/atrust 不允许依赖 %s；"+
					"aTrust 与 V5VPN 必须在包级完全隔离（§14.5.2）", dep)
			}
			// 子包也要拦：internal/protocol/xxx 同样越界。
			if strings.HasPrefix(dep, bad+"/") {
				t.Errorf("internal/atrust 不允许依赖 %s；"+
					"aTrust 与 V5VPN 必须在包级完全隔离（§14.5.2）", dep)
			}
		}
	}
}

// TestNoReverseDependency 验证 V5VPN 侧也没有反向依赖 atrust。
//
// 这条更微妙：即便 aTrust 自己不依赖 protocol，只要 protocol 反过来
// 依赖 atrust，两边的改动仍然会互相牵连。
func TestNoReverseDependency(t *testing.T) {
	modPath, err := modulePath()
	if err != nil {
		t.Skipf("无法取得模块路径: %v", err)
	}

	for _, pkg := range []string{"/internal/protocol", "/internal/proxy"} {
		deps, err := listDeps(modPath + pkg)
		if err != nil {
			t.Skipf("go list %s 不可用: %v", pkg, err)
		}
		for _, dep := range deps {
			if dep == modPath+"/internal/atrust" || strings.HasPrefix(dep, modPath+"/internal/atrust/") {
				t.Errorf("%s 不允许依赖 %s；反向依赖同样会破坏隔离（§14.5.2）", pkg, dep)
			}
		}
	}
}

func modulePath() (string, error) {
	out, err := exec.Command("go", "list", "-m").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func listDeps(pkg string) ([]string, error) {
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		return nil, err
	}
	var deps []string
	for _, line := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			deps = append(deps, s)
		}
	}
	return deps, nil
}
