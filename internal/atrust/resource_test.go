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

// ─── 真实资源树结构（§4.2 / libreatrust resource.rs）───────────────

// realTree 是真实网关 clientResource 的形状，与 mock 下发的完全一致。
const realTree = `{
  "appList": {
    "code": 0,
    "data": {
      "appInfo": [
        {
          "id": "g1",
          "name": "演示资源",
          "accessModel": "L3VPN",
          "apps": [
            {
              "id": "a1",
              "name": "Mock 控制台",
              "nodeGroupId": "n1",
              "addressList": [
                {"protocol": "tcp", "port": "8443", "host": "127.0.0.1"}
              ]
            },
            {
              "id": "a2",
              "name": "内网 Web",
              "nodeGroupId": "n1",
              "addressList": [
                {"protocol": "tcp", "port": "443", "host": "example.internal", "ip": ["10.15.45.163"]},
                {"protocol": "tcp", "port": "443", "host": "10.15.45.163"}
              ]
            }
          ]
        },
        {
          "id": "g2",
          "name": "内网网段",
          "apps": [
            {
              "id": "a3",
              "name": "办公网段",
              "addressList": [
                {"protocol": "tcp", "port": "0", "host": "10.20.0.0/16"}
              ]
            }
          ]
        }
      ]
    }
  },
  "sdpPolicy": {"code": 0, "data": {}}
}`

func parseTree(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("解析测试数据: %v", err)
	}
	return m
}

// TestExtractResourcesRealTree 是这次修复的核心用例。
//
// 修复前：appList 名下不是数组而是 {code,data:{appInfo}}，旧实现直接放弃，
// 返回空列表且 extraKeys 里也没有 appList（因为键名认识）——于是
// 「资源树解析失败」完全静默。真实客户端登录成功后看到的空白资源列表
// 就是这个原因。
func TestExtractResourcesRealTree(t *testing.T) {
	items, _ := ExtractResources(parseTree(t, realTree))

	// 5 条地址条目：a1(1) + a2(2) + a3(1) = 4
	if len(items) != 4 {
		t.Fatalf("资源数 = %d，期望 4。实际: %+v", len(items), items)
	}

	first := items[0]
	if first.Name != "Mock 控制台" {
		t.Errorf("name = %q", first.Name)
	}
	if first.RemoteIP != "127.0.0.1" || first.RemotePort != "8443" {
		t.Errorf("地址 = %s:%s", first.RemoteIP, first.RemotePort)
	}
	if first.Protocol != "tcp" {
		t.Errorf("protocol = %q", first.Protocol)
	}
	if first.MapID != "a1" {
		t.Errorf("mapId = %q", first.MapID)
	}
	if first.Status != "active" {
		t.Errorf("status = %q", first.Status)
	}
}

// TestExtractResourcesExpandsAddressList 验证「一条应用多条地址」展开成多行。
//
// 同一个应用可能有域名入口和内网 IP 入口，它们是**不同的路由**，
// 合并成一行会丢掉其中一条。
func TestExtractResourcesExpandsAddressList(t *testing.T) {
	items, _ := ExtractResources(parseTree(t, realTree))

	var hosts []string
	for _, it := range items {
		if it.Name == "内网 Web" {
			hosts = append(hosts, it.RemoteIP)
		}
	}
	if len(hosts) != 2 {
		t.Fatalf("内网 Web 应有 2 条地址，实际 %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "example.internal" || hosts[1] != "10.15.45.163" {
		t.Errorf("地址顺序或取值不符: %v", hosts)
	}
}

// TestExtractResourcesPortZeroIsWildcard 验证 port "0" 的展示。
//
// aTrust 用 0 表示「全部端口」。直接显示 :0 会让人以为要连 0 端口。
func TestExtractResourcesPortZeroIsWildcard(t *testing.T) {
	items, _ := ExtractResources(parseTree(t, realTree))
	for _, it := range items {
		if it.Name == "办公网段" {
			if it.RemotePort != "*" {
				t.Fatalf("port 0 应显示为 *，实际 %q", it.RemotePort)
			}
			if it.RemoteIP != "10.20.0.0/16" {
				t.Fatalf("CIDR 应原样保留，实际 %q", it.RemoteIP)
			}
			return
		}
	}
	t.Fatal("未找到「办公网段」")
}

// TestExtractResourcesAppWithoutAddress 验证没有 addressList 的应用不丢。
func TestExtractResourcesAppWithoutAddress(t *testing.T) {
	raw := `{"appList":{"code":0,"data":{"appInfo":[
	  {"id":"g","name":"组","apps":[{"id":"a","name":"无地址应用"}]}
	]}}}`
	items, _ := ExtractResources(parseTree(t, raw))
	if len(items) != 1 {
		t.Fatalf("资源数 = %d，期望 1", len(items))
	}
	if items[0].Name != "无地址应用" || items[0].MapID != "a" {
		t.Fatalf("字段不符: %+v", items[0])
	}
}

// TestExtractResourcesNameFallsBackToGroup 验证应用没名字时用分组名兜底。
func TestExtractResourcesNameFallsBackToGroup(t *testing.T) {
	raw := `{"appList":{"code":0,"data":{"appInfo":[
	  {"id":"g","name":"分组名","apps":[{"id":"a","addressList":[{"protocol":"tcp","port":"22","host":"10.1.1.1"}]}]}
	]}}}`
	items, _ := ExtractResources(parseTree(t, raw))
	if len(items) != 1 || items[0].Name != "分组名" {
		t.Fatalf("分组名兜底失败: %+v", items)
	}
}

// TestExtractResourcesTreeBeatsFlat 验证树形结构优先于扁平数组。
//
// 两者同时存在时（网关做兼容会同时下发新旧两种形状），应当用树形那份：
// 扁平那份通常是旧版本残留，字段更少。
func TestExtractResourcesTreeBeatsFlat(t *testing.T) {
	raw := `{
	  "appList": {"code":0,"data":{"appInfo":[
	    {"id":"g","name":"树","apps":[{"id":"a","name":"树里的应用",
	      "addressList":[{"protocol":"tcp","port":"443","host":"10.9.9.9"}]}]}
	  ]}},
	  "resources": [{"name":"扁平里的应用","host":"10.8.8.8","port":"80"}]
	}`
	items, _ := ExtractResources(parseTree(t, raw))
	if len(items) != 1 || items[0].Name != "树里的应用" {
		t.Fatalf("未优先使用树形结构: %+v", items)
	}
}

// TestExtractResourcesRealTreeExtraKeys 验证 sdpPolicy 等非资源键被上报。
func TestExtractResourcesRealTreeExtraKeys(t *testing.T) {
	_, extra := ExtractResources(parseTree(t, realTree))
	found := false
	for _, k := range extra {
		if k == "sdpPolicy" {
			found = true
		}
		if k == "appList" {
			t.Error("appList 是已知键，不应出现在 extraKeys 里")
		}
	}
	if !found {
		t.Errorf("sdpPolicy 应被列为未识别键（用于排查），实际: %v", extra)
	}
}
