package atrust

// resource_test.go — 资源投影的容错边界。
//
// 这一层的价值不在"正常情况能解出来"，而在"网关换了个键名时
// 不会静默变成空列表"。所以测的重点是退化路径。

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestExtractResourcesFromAppListV2(t *testing.T) {
	raw := map[string]any{
		"appListV2": []any{
			map[string]any{"name": "OA", "host": "10.0.0.5", "port": float64(443), "protocol": "tcp"},
			map[string]any{"appName": "ERP", "addr": "10.0.0.6", "port": "8080"},
		},
		"uemPolicy": map[string]any{},
	}

	items, extra := ExtractResources(raw)
	if len(items) != 2 {
		t.Fatalf("期望 2 条资源，实际 %d: %+v", len(items), items)
	}

	if items[0].Name != "OA" || items[0].RemoteIP != "10.0.0.5" || items[0].RemotePort != "443" {
		t.Errorf("第一条解析错误: %+v", items[0])
	}
	// 数字型 port 必须输出成 "443" 而不是 "443.000000"。
	if strings.Contains(items[0].RemotePort, ".") {
		t.Errorf("端口格式错误: %q", items[0].RemotePort)
	}
	// 备选键名 appName / addr 必须命中。
	if items[1].Name != "ERP" || items[1].RemoteIP != "10.0.0.6" {
		t.Errorf("备用键名未命中: %+v", items[1])
	}
	if items[0].Status != "active" {
		t.Errorf("Status 默认值错误: %q", items[0].Status)
	}

	// uemPolicy 不在 resourceArrayKeys 里，应作为未知键上报。
	if len(extra) != 1 || extra[0] != "uemPolicy" {
		t.Errorf("未知顶层键上报错误: %v", extra)
	}
}

// TestExtractResourcesPrefersV2 验证 appListV2 优先于 appList。
// 两者同时存在时取错的版本会拿到过期的资源集。
func TestExtractResourcesPrefersV2(t *testing.T) {
	raw := map[string]any{
		"appList":   []any{map[string]any{"name": "old"}},
		"appListV2": []any{map[string]any{"name": "new"}},
	}
	items, _ := ExtractResources(raw)
	if len(items) != 1 || items[0].Name != "new" {
		t.Fatalf("未优先使用 appListV2: %+v", items)
	}
}

// TestExtractResourcesUnknownShape 是核心退化用例：
// 形状不认识时必须返回空列表 + 全部顶层键，而不是 panic 或 nil 指针。
func TestExtractResourcesUnknownShape(t *testing.T) {
	raw := map[string]any{
		"someNewKey": []any{map[string]any{"name": "x"}},
		"version":    "3.0",
	}
	items, extra := ExtractResources(raw)
	if len(items) != 0 {
		t.Fatalf("未知形状不应解出资源: %+v", items)
	}
	if len(extra) != 2 {
		t.Fatalf("未知形状应上报全部顶层键，实际 %v", extra)
	}
}

func TestExtractResourcesNilAndEmpty(t *testing.T) {
	for name, raw := range map[string]map[string]any{
		"nil":        nil,
		"empty":      {},
		"emptyArray": {"appListV2": []any{}},
	} {
		items, _ := ExtractResources(raw)
		if len(items) != 0 {
			t.Errorf("%s: 期望空列表，实际 %+v", name, items)
		}
	}
}

// TestExtractResourcesWrappedInData 覆盖 {"appList":{"data":[...]}} 这种包装。
func TestExtractResourcesWrappedInData(t *testing.T) {
	raw := map[string]any{
		"appList": map[string]any{
			"code": float64(0),
			"data": []any{map[string]any{"name": "wrapped", "ip": "192.0.2.1"}},
		},
	}
	items, _ := ExtractResources(raw)
	if len(items) != 1 || items[0].Name != "wrapped" || items[0].RemoteIP != "192.0.2.1" {
		t.Fatalf("包装层未解开: %+v", items)
	}
}

// TestResourceNameFallsBackToAddress 验证无名资源用地址兜底。
func TestResourceNameFallsBackToAddress(t *testing.T) {
	items, _ := ExtractResources(map[string]any{
		"appList": []any{map[string]any{"host": "10.1.2.3"}},
	})
	if len(items) != 1 || items[0].Name != "10.1.2.3" {
		t.Fatalf("名称兜底失败: %+v", items)
	}
}

// TestResourceJSONShapeMatchesV5VPN 守护与 protocol.VPNResource 的字段一致性。
//
// 两个包之间刻意没有类型依赖（§14.5.2 的边界一），所以这里用序列化
// 后的键集合做等价证明：前端渲染函数按这些键读值，少一个就是空列。
func TestResourceJSONShapeMatchesV5VPN(t *testing.T) {
	buf, err := json.Marshal(Resource{
		Name: "n", Protocol: "p", RemoteIP: "1.1.1.1", RemotePort: "443",
		LocalProxy: "127.0.0.1:1000", Status: "active", MapID: "m", AccessURL: "u",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf, &got); err != nil {
		t.Fatal(err)
	}

	// 与 internal/protocol/models.go 的 VPNResource json tag 逐项对齐。
	want := []string{"name", "protocol", "remoteIp", "remotePort", "localProxy", "status", "mapId", "accessUrl"}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("缺少字段 %q，前端对应列会空白。实际: %v", k, reflect.ValueOf(got).MapKeys())
		}
	}
	if len(got) != len(want) {
		t.Errorf("字段数 %d，期望 %d: %v", len(got), len(want), got)
	}
}

// TestFirstStringSkipsBool 验证布尔值不会被当成地址。
func TestFirstStringSkipsBool(t *testing.T) {
	m := map[string]any{"host": true, "addr": "10.0.0.9"}
	if got := firstString(m, "host", "addr"); got != "10.0.0.9" {
		t.Fatalf("布尔值未被跳过: %q", got)
	}
	m2 := map[string]any{"host": ""}
	if got := firstString(m2, "host", "addr"); got != "" {
		t.Fatalf("空串不应返回值: %q", got)
	}
}
