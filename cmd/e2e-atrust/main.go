package main

// e2e_atrust.go — 用 v5vpn-rea 的 aTrust 客户端对撞 mock 网关。
//
// 与官方客户端方向相反：官方客户端验证「我们读懂了协议吗」，
// 这个脚本验证「我们自己的客户端实现能走通同一条协议」。两者互补。
//
// 用法（在仓库根目录）：
//
//	go run ./cmd/e2e-atrust -gw https://127.0.0.1:8443 -user user1@local -pass any
//
// 它做的事：
//  1. 探测网关类型
//  2. 登录（authConfig → psw → authCheck → onlineInfo）
//  3. 拉资源树并打印解析结果
//  4. 对每条资源试一次数据面选路，确认能拿到 appId 与线路

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/atrust"
)

func main() {
	gw := flag.String("gw", "https://127.0.0.1:8443", "mock 网关地址")
	user := flag.String("user", "user1@local", "用户名")
	pass := flag.String("pass", "any", "口令")
	noDial := flag.Bool("no-dial", false, "只做控制面，不尝试数据面建连")
	flag.Parse()

	logf := func(format string, args ...any) {
		fmt.Printf("  [client] "+format+"\n", args...)
	}

	c, err := atrust.NewClient(*gw, atrust.Options{
		InsecureSkipVerify: true,
		Logf:               logf,
	})
	if err != nil {
		fail("NewClient: %v", err)
	}
	defer c.Close()

	fmt.Println("=== 1. 探测网关类型 ===")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.Detect(ctx); err != nil {
		fail("不是 aTrust 网关: %v", err)
	}
	fmt.Println("  ✓ 是 aTrust 网关")

	fmt.Println("\n=== 2. 登录 ===")
	cfg, err := c.Authenticate(ctx, *user, *pass)
	if err != nil {
		fail("登录失败: %v", err)
	}
	fmt.Printf("  ✓ 登录成功，sid=%s…\n", trunc(c.SidTicket(), 16))
	if sk := c.SignKeyHex(); sk != "" {
		fmt.Printf("  signKey 已派生（%d hex）\n", len(sk))
	} else {
		fmt.Println("  ⚠ signKey 未派生")
	}
	if cfg != nil {
		d := cfg.AntiMITMAttackData
		fmt.Printf("  antiMITM: enable=%d challengeLen=%d\n", d.Enable, len(d.Challenge))
	}

	// 设备标识：数据面必需，且必须跨次运行保持不变。
	dir, _ := os.UserConfigDir()
	id, err := atrust.EnsureDeviceID(dir)
	if err != nil {
		fmt.Printf("  ⚠ deviceId 生成失败: %v\n", err)
	} else {
		c.SetDeviceID(id)
		fmt.Printf("  deviceId=%s（持久化于 %s）\n", id, dir)
	}

	fmt.Println("\n=== 3. 拉取资源树 ===")
	raw, err := c.ClientResource(ctx)
	if err != nil {
		fail("clientResource 失败: %v", err)
	}
	items, unknown := atrust.ExtractResources(raw)
	fmt.Printf("  ✓ 解析出 %d 条资源（未识别顶层键: %v）\n", len(items), unknown)
	for i, r := range items {
		fmt.Printf("     %-2d %-26s %s://%s:%s\n", i+1, r.Name, r.Protocol, r.RemoteIP, r.RemotePort)
	}

	if *noDial {
		fmt.Println("\n完成（跳过数据面）。")
		return
	}

	fmt.Println("\n=== 4. 数据面选路 ===")
	fmt.Println("  mock 不提供 441 数据面，预期每条都失败；")
	fmt.Println("  要确认的是错误形态能区分「无线路」与「线路不可达」。")
	for _, r := range items {
		if r.RemoteIP == "" || r.RemotePort == "" || r.RemotePort == "*" || r.RemotePort == "0" {
			continue
		}
		port := 0
		if _, err := fmt.Sscanf(r.RemotePort, "%d", &port); err != nil || port == 0 {
			continue
		}
		dctx, dcancel := context.WithTimeout(context.Background(), 6*time.Second)
		conn, derr := c.DialTCP(dctx, r.RemoteIP, port)
		dcancel()
		if derr == nil {
			_ = conn.Close()
			fmt.Printf("     %-26s ✓ 隧道建立成功\n", r.Name)
			continue
		}
		fmt.Printf("     %-26s ✗ %v\n", r.Name, derr)
	}

	fmt.Println("\n完成。")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func fail(format string, args ...any) {
	fmt.Printf("✗ "+format+"\n", args...)
	os.Exit(1)
}
