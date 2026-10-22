package main

// main.go — 用 v5vpn 客户端协议库对撞本地/远程 V5VPN 网关。
//
// 对应 cmd/e2e-atrust，用于在 CLI 环境快速验证 V5VPN 协议握手、
// 口令登录、双因素认证与内网资源拉取流程。
//
// 用法（在仓库根目录）：
//
//	# 1. 启动 mock 网关：
//	go run ./cmd/mock-v5vpn -addr 127.0.0.1:8443 -mode pwd-only
//
//	# 2. 运行 e2e 测试对撞：
//	go run ./cmd/e2e-v5vpn -gw 127.0.0.1 -port 8443 -user admin -pwd admin123

import (
	"flag"
	"fmt"
	"os"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func main() {
	gwIP := flag.String("gw", "127.0.0.1", "网关 IP 或域名")
	gwPort := flag.Int("port", 8443, "网关端口")
	user := flag.String("user", "admin", "用户名")
	pwd := flag.String("pwd", "admin123", "密码")
	verifyCode := flag.String("code", "", "图形验证码（如果需要）")
	algo := flag.Int("algo", 0, "算法: 0 标准 TLS, 1 国密")
	flag.Parse()

	logf := func(level, format string, args ...any) {
		fmt.Printf("  [%s] %s\n", level, fmt.Sprintf(format, args...))
	}

	fmt.Println("=== 1. 初始化客户端与协议握手 ===")
	client := protocol.NewClient(*gwIP, *gwPort, *algo, logf)

	ver, err := client.Handshake()
	if err != nil {
		fail("Handshake 失败: %v", err)
	}
	fmt.Printf("  ✓ 握手成功: Version %s.%s\n", ver.Major, ver.Minor)

	fmt.Println("\n=== 2. 口令身份认证 ===")
	authResp, err := client.AuthOnly(*user, *pwd, *verifyCode)
	if err != nil {
		fail("认证失败: %v", err)
	}
	fmt.Printf("  ✓ 认证成功: Result Code=%s, SessionID=%s\n", authResp.Result.Code, client.SessionID)

	fmt.Println("\n=== 3. 拉取门户资源 ===")
	info, err := client.FetchIntegration()
	if err != nil {
		fail("获取内网资源失败: %v", err)
	}
	resList := info.ResourceList.TCPUDPResources
	fmt.Printf("  ✓ 成功获取 %d 条内网映射资源:\n", len(resList))
	for i, r := range resList {
		addr := ""
		if len(r.IPConfigs) > 0 {
			addr = r.IPConfigs[0].Addr
		}
		fmt.Printf("     %-2d %-24s %s %s:%s\n", i+1, r.Name, r.Protocol, addr, r.Port)
	}

	fmt.Println("\n完成。")
}

func fail(format string, args ...any) {
	fmt.Printf("✗ "+format+"\n", args...)
	os.Exit(1)
}
