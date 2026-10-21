package atrust

// e2e_mock_test.go — 用真实的 mock 网关做端到端互操作验证。
//
// 与 login_test.go 的 httptest 不同：这里连的是**独立进程**里的 mock。
// mock 是按同一份规范单独实现的，两边能对上说明规范读对了，
// 而不是我们的实现跟自己的测试互相印证。
//
// 默认跳过。要跑：
//
//	go test ./internal/atrust/ -run TestE2EAgainstMock -v
//	ATRUST_MOCK=1 go test ./internal/atrust/ -run TestE2EAgainstMock -v
//
// 前提：mock 正在 8443 监听（atrust-mock.exe -addr 127.0.0.1:8443）。

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestE2EAgainstMock(t *testing.T) {
	addr := os.Getenv("ATRUST_MOCK_ADDR")
	if addr == "" {
		addr = "https://127.0.0.1:8443"
	}

	// 先探一下端口，没起就跳过而不是失败——这个测试依赖外部进程。
	probe, err := NewClient(addr, Options{InsecureSkipVerify: true, Timeout: 2 * time.Second})
	if err != nil {
		t.Skipf("无法建立客户端: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := probe.Detect(ctx); err != nil {
		probe.Close()
		t.Skipf("mock 未运行或不是 aTrust 网关（%s）: %v", addr, err)
	}
	probe.Close()

	c, err := NewClient(addr, Options{
		InsecureSkipVerify: true,
		Logf:               t.Logf,
	})
	if err != nil {
		t.Fatalf("NewClient 失败: %v", err)
	}
	defer c.Close()

	// 1. entranceConfig 必须是 JS 而不是 JSON
	ent, err := c.EntranceConfig(ctx)
	if err != nil {
		t.Fatalf("EntranceConfig 失败: %v", err)
	}
	if e, ok := ent["entrance"].(map[string]any); !ok || e["type"] != "portal" {
		t.Fatalf("entrance.type 不是 portal: %v", ent)
	}

	// 2. 完整登录链
	res, err := c.Login(ctx, "e2e-user@local", "e2e-password")
	if err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	if len(res.SidTicket) != 64 {
		t.Fatalf("sidTicket 长度 = %d, 期望 64", len(res.SidTicket))
	}
	if res.AuthConfig == nil {
		t.Fatal("authConfig 为空")
	}
	if res.AuthConfig.PubKeyExp != "65537" {
		t.Fatalf("pubKeyExp = %q, 期望 65537", res.AuthConfig.PubKeyExp)
	}
	if res.Resources == nil {
		t.Fatal("资源树为空")
	}

	// 3. 会话交换（表单编码）
	sid := c.SidTicket()
	if _, err := c.SessionIDExchange(ctx, sid); err != nil {
		t.Fatalf("SessionIDExchange 失败: %v", err)
	}
	te, err := c.TicketExchange(ctx, sid)
	if err != nil {
		t.Fatalf("TicketExchange 失败: %v", err)
	}
	if len(te.SidTicket) != 64 {
		t.Fatalf("ticketExchange 返回的 sidTicket 长度 = %d", len(te.SidTicket))
	}

	// 4. 登出
	if err := c.LogoutAndClear(ctx); err != nil {
		t.Fatalf("LogoutAndClear 失败: %v", err)
	}
	if c.SidTicket() != "" {
		t.Fatal("登出后本地会话未清空")
	}
}
