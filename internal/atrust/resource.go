package atrust

// resource.go — 把资源树投影成 UI 能直接渲染的形状。
//
// 为什么要单独一层：/controller/v1/user/clientResource 的响应结构尚未与
// 真实网关逐字段比对过（mock 只提供了最小可用集，规范 §8.1 提到资源在
// appList / appListV2 里）。直接把这个 map 交给 UI 会让"猜错字段名"
// 变成静默的空列表，而不是一个可以定位的问题。
//
// 所以这里做**宽容解析**：按已知的几个位置依次找数组，找到就用，
// 找不到就返回空切片并把原始键名记下来。这样对未知形状不会崩，
// 而且排查时能看到网关到底给了什么。

import (
	"encoding/json"
	"fmt"
)

// Resource 是 UI 侧的资源视图。
//
// 字段名（json tag）与 V5VPN 侧的 protocol.VPNResource 保持一致，
// 目的是让前端复用同一个渲染函数。两个包之间没有类型依赖——
// 这里只是让序列化后的形状相同。
type Resource struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	RemoteIP   string `json:"remoteIp"`
	RemotePort string `json:"remotePort"`
	LocalProxy string `json:"localProxy"`
	Status     string `json:"status"`
	MapID      string `json:"mapId,omitempty"`
	AccessURL  string `json:"accessUrl,omitempty"`
}

// resourceArrayKeys 是可能承载资源数组的键，按可信度排列。
//
// 来源：aTrustCore.dll 的 JSON Schema 与 §8.1 的字段表。
// appListV2 优先于 appList —— V2 是当前版本，V1 是兼容路径。
var resourceArrayKeys = []string{
	"appListV2",
	"appList",
	"resource",
	"resources",
	"appListInfo",
}

// ExtractResources 从资源树原始响应里投影出资源列表。
//
// 返回值 extraKeys 是响应里出现但未被识别的顶层键，供调用方记录——
// 它的用途是：如果真实网关用的键不在 resourceArrayKeys 里，日志里能
// 直接看到候选，而不是只看到一个空列表。
func ExtractResources(raw map[string]any) (items []Resource, extraKeys []string) {
	if raw == nil {
		return []Resource{}, nil
	}

	var arr []any
	for _, key := range resourceArrayKeys {
		v, ok := raw[key]
		if !ok {
			continue
		}
		// 有的网关把数组包在 {"code":0,"data":[...]} 里。
		if m, isMap := v.(map[string]any); isMap {
			if inner, has := m["data"]; has {
				v = inner
			}
		}
		if a, isArr := v.([]any); isArr && len(a) > 0 {
			arr = a
			break
		}
	}

	for k := range raw {
		known := false
		for _, key := range resourceArrayKeys {
			if k == key {
				known = true
				break
			}
		}
		if !known {
			extraKeys = append(extraKeys, k)
		}
	}

	if arr == nil {
		// 返回 nil 而不是 nil 切片会让 JSON 编码成 null，前端 renderResources
		// 里的 resources.length 就会抛 TypeError。空切片编码成 []。
		return []Resource{}, extraKeys
	}

	items = make([]Resource, 0, len(arr))
	for _, elem := range arr {
		m, ok := elem.(map[string]any)
		if !ok {
			continue
		}
		items = append(items, resourceFromMap(m))
	}
	return items, extraKeys
}

// resourceFromMap 从单个资源条目里尽力提取字段。
//
// 每个字段都试多个候选键名：aTrust 的不同版本/不同网关在命名上并不统一
// （host vs addr vs ip，port 可能是数字也可能是字符串）。
func resourceFromMap(m map[string]any) Resource {
	r := Resource{
		Name:       firstString(m, "name", "appName", "resourceName", "title"),
		Protocol:   firstString(m, "protocol", "type", "appType"),
		RemoteIP:   firstString(m, "host", "addr", "ip", "address", "domain"),
		RemotePort: firstString(m, "port", "remotePort", "destPort"),
		AccessURL:  firstString(m, "accessUrl", "url", "accessURL"),
		MapID:      firstString(m, "mapId", "id", "appId"),
	}
	r.LocalProxy = firstString(m, "localProxy", "localAddr", "proxy")

	if r.Name == "" {
		// 没有名字的资源在界面上不可用；用地址兜底，避免一条空行。
		r.Name = r.RemoteIP
	}
	r.Status = "active"
	return r
}

// firstString 返回第一个存在且可转成字符串的值。
//
// 数字类型的端口很常见（"port": 443），所以要处理 json.Number 与 float64。
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return t
			}
		case json.Number:
			return t.String()
		case float64:
			// 443.0 要输出成 "443" 而不是 "443.000000"
			if t == float64(int64(t)) {
				return fmt.Sprintf("%d", int64(t))
			}
			return fmt.Sprintf("%g", t)
		case bool:
			// 布尔值不是有意义的地址/名称，跳过。
			continue
		}
	}
	return ""
}
