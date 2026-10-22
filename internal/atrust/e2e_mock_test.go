package atrust

// e2e_mock_test.go — 用 in-repo mock 网关做端到端互操作验证。
//
// 与 login_test.go 的 httptest 不同：这里连的是**独立进程**里的 mock
// （test/mock/atrust，见 mockproc_test.go）。mock 是按同一份规范单独实现的，
// 两边能对上说明规范读对了，而不是我们的实现跟自己的测试互相印证。
//
// 默认自动拉起 mock 子进程、随机端口，`go test ./internal/atrust/` 一条命令即可。
//
// 想连一个**已在跑**的外部 mock（例如对撞真实网关、或验证官方客户端用的常驻实例）：
//
//	ATRUST_MOCK_URL=https://127.0.0.1:8443 go test ./internal/atrust/ -run TestE2EAgainstMock -v
//
// 设了该变量就不再自拉起，而是直接连过去；连不上则 skip（外部依赖不该让 CI 变红）。

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestE2EAgainstMock(t *testing.T) {
	c := newMockBackedClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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

	// 3. 资源树解析：mock 下发固定分组，客户端应能解出非空资源列表。
	//    这一步证明"官方渲染层的数据形状"与我们的 ExtractResources 对得上。
	items, _ := ExtractResources(res.Resources)
	if len(items) == 0 {
		t.Fatalf("ExtractResources 解出 0 条资源，mock 却下发了 appInfo 分组: %v", res.Resources)
	}
	t.Logf("解析出 %d 条资源", len(items))

	// 4. 会话交换（表单编码）
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

	// 5. 登出
	if err := c.LogoutAndClear(ctx); err != nil {
		t.Fatalf("LogoutAndClear 失败: %v", err)
	}
	if c.SidTicket() != "" {
		t.Fatal("登出后本地会话未清空")
	}
}

// newMockBackedClient 返回一个连到可用 mock 的客户端。
//
// 外部地址（ATRUST_MOCK_URL 非空）连不上就 skip——那是调用方的环境，不该让测试变红；
// 自拉起的 mock 起不来是真失败，直接 Fatal。
func newMockBackedClient(t *testing.T) *Client {
	t.Helper()

	base := os.Getenv("ATRUST_MOCK_URL")
	external := base != ""
	if !external {
		base = startMock(t).BaseURL
	}

	probe, err := NewClient(base, Options{InsecureSkipVerify: true, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	pctx, pcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer pcancel()
	if err := probe.Detect(pctx); err != nil {
		probe.Close()
		if external {
			t.Skipf("外部 mock 未运行或不是 aTrust 网关（%s）: %v", base, err)
		}
		t.Fatalf("自拉起的 mock 未就绪: %v", err)
	}
	probe.Close()

	c, err := NewClient(base, Options{
		InsecureSkipVerify: true,
		Logf:               t.Logf,
	})
	if err != nil {
		t.Fatalf("NewClient 失败: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}
