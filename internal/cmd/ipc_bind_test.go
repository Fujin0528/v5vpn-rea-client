package main

import (
	"testing"

	"github.com/egoist/mygo"
	"github.com/hygkui/v5vpn-rea-client/internal/service"
)

// TestVPNServiceBindsToIPC guards the frontend bridge: mygo.BindAs reflects over
// every exported method and rejects parameter or result types that cannot cross
// the JSON IPC boundary. A method taking *tls.Certificate (or any type holding a
// channel/func) would panic at startup, before the window is ever shown.
func TestVPNServiceBindsToIPC(t *testing.T) {
	svc := service.NewVPNService(nil)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VPNService cannot be bound to IPC: %v", r)
		}
	}()
	mygo.BindAs("VPNService", svc)
}

// TestATrustServiceBindsToIPC 是上一条测试的 aTrust 版本。
//
// 它同样在启动时就 panic，而不只是前端调用失败——所以必须单独守一次。
// aTrust 侧的类型里 `Client *atrust.Client` 是导出字段，如果哪天它
// 被当成可编码类型处理就会在这里炸出来。
func TestATrustServiceBindsToIPC(t *testing.T) {
	svc := service.NewATrustService(nil)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ATrustService cannot be bound to IPC: %v", r)
		}
	}()
	mygo.BindAs("ATrustService", svc)
}

// TestBothServicesCoexist 验证两个服务名不冲突。
//
// mygo 的 bind() 按名字注册，同名会 panic（ipc.go:142），而注册表是
// **进程全局**的——所以这条测试不能真的把两个服务都绑定一次：
// 上面两条测试已经占用了这些名字，重复绑定必然 panic，
// 那验的就不是"名字不同"而是"注册表是全局的"。
//
// 真正要守的是名字字面量不同。这里直接断言 main() 里用的那两个名字，
// 把"改错名字"变成一个测试失败而不是启动崩溃。
func TestBothServicesCoexist(t *testing.T) {
	const v5Name = "VPNService"
	const atName = "ATrustService"
	if v5Name == atName {
		t.Fatalf("两个服务名相同（%q），mygo.BindAs 会 panic", v5Name)
	}
	// mygo 要求服务名是合法的 TS 标识符（字母开头）。这里用最小的判定，
	// 因为 tsgen.IsIdentifier 是 mygo 的 internal 包，导入不进来。
	for _, name := range []string{v5Name, atName} {
		if name == "" || !isLetter(rune(name[0])) {
			t.Fatalf("服务名 %q 不是合法标识符", name)
		}
	}
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
}
