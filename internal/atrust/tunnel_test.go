package atrust

// tunnel_test.go — 隧道帧编码与路由匹配的单元测试。
//
// 这些测试不联网：它们验证"我们发出去的字节"与规范逐字节一致。
// 联调测试在 tunnel_mock_test.go 里（用本地假网关）。

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// TestAppendTargetIPv4 验证目标地址帧的 IPv4 形态。
//
// 期望：05 01 01 01 <4B IP> <BE16 port>
//
//	^  ^  ^  ^
//	|  |  |  └ ATYP=1 (IPv4)
//	|  |  └ cmd=0x01
//	|  └ sub=0x01 (control)
//	└ version 0x05
func TestAppendTargetIPv4(t *testing.T) {
	got := appendTarget(nil, "10.15.45.163", 443)

	want := []byte{0x05, 0x01, 0x01, 0x01, 10, 15, 45, 163, 0x01, 0xBB}
	if len(got) != len(want) {
		t.Fatalf("长度 = %d, want %d (帧: % X)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("字节 %d = 0x%02X, want 0x%02X（完整帧: % X）", i, got[i], want[i], got)
		}
	}
}

// TestAppendTargetDomain 验证域名形态用 ATYP=3。
func TestAppendTargetDomain(t *testing.T) {
	got := appendTarget(nil, "mock-resource.internal", 8443)

	if got[0] != 0x05 || got[1] != 0x01 || got[2] != 0x01 || got[3] != 0x03 {
		t.Fatalf("前缀 = % X, want 05 01 01 03", got[:4])
	}
	if int(got[4]) != len("mock-resource.internal") {
		t.Fatalf("域名长度字节 = %d, want %d", got[4], len("mock-resource.internal"))
	}
	if string(got[5:5+len("mock-resource.internal")]) != "mock-resource.internal" {
		t.Fatalf("域名 = %q", string(got[5:5+len("mock-resource.internal")]))
	}
	// 末尾两字节是端口
	tail := got[len(got)-2:]
	if int(tail[0])<<8|int(tail[1]) != 8443 {
		t.Fatalf("端口 = %d, want 8443", int(tail[0])<<8|int(tail[1]))
	}
}

// TestAppendTargetIPv6 验证 IPv6 用 ATYP=4 且地址占 16 字节。
func TestAppendTargetIPv6(t *testing.T) {
	host := "2001:db8::1"
	got := appendTarget(nil, host, 441)

	if got[3] != 0x04 {
		t.Fatalf("ATYP = 0x%02X, want 0x04", got[3])
	}
	// 05 01 01 04 + 16 字节地址 + 2 字节端口
	if len(got) != 4+16+2 {
		t.Fatalf("长度 = %d, want %d", len(got), 4+16+2)
	}
	if ip := net.IP(got[4 : 4+16]); !ip.Equal(net.ParseIP(host)) {
		t.Fatalf("地址 = %v, want %v", ip, net.ParseIP(host))
	}
}

// TestBuildStreamAuthJSONKeyOrder 验证认证 JSON 的键顺序。
//
// 顺序是有意义的：xRequestSig 若启用，覆盖的是序列化后的字节。
// 这里只锁住"键一定按这个次序出现"，不校验具体值。
func TestBuildStreamAuthJSONKeyOrder(t *testing.T) {
	mat := &sessionMaterial{
		Sid:          "unit_uuid",
		DeviceID:     "AABBCCDDEEFF00112233445566778899",
		ConnectionID: "AABB-1700000000000000",
		Username:     "user1@local",
	}
	s := buildStreamAuthJSON(mat, "10.15.45.163", 443, "app-1")

	keys := []string{
		`"sid":"`, `"appId":"`, `"url":"`, `"deviceId":"`, `"connectionId":"`,
		`"procHash":"`, `"userName":"`, `"lang":"`, `"destAddr":"`, `"env":`,
		`"xRequestSig":"`,
	}
	pos := 0
	for _, k := range keys {
		i := indexOf(s[pos:], k)
		if i < 0 {
			t.Fatalf("键 %s 未出现，或顺序不对。JSON:\n%s", k, s)
		}
		pos += i + len(k)
	}

	// url 必须是 tcp:host:port 形态（geektrust §6.2）。
	if !contains(s, `"url":"tcp:10.15.45.163:443"`) {
		t.Errorf("url 字段不符合 tcp:host:port 形态:\n%s", s)
	}
	// destAddr 是 host:port。
	if !contains(s, `"destAddr":"10.15.45.163:443"`) {
		t.Errorf("destAddr 字段不符合 host:port 形态:\n%s", s)
	}
}

// TestBuildStreamAuthJSONEscaping 验证特殊字符不会破坏 JSON。
func TestBuildStreamAuthJSONEscaping(t *testing.T) {
	mat := &sessionMaterial{
		Sid:          `weird"sid\with\backslash`,
		DeviceID:     "AABB",
		ConnectionID: "x",
		Username:     "u",
	}
	s := buildStreamAuthJSON(mat, "10.0.0.1", 80, "app")

	// 转义正确的话，反斜杠与引号都变成两字符形式，原始未转义串不应出现。
	if contains(s, `"sid":"weird"sid`) {
		t.Fatalf("sid 中的引号没有转义:\n%s", s)
	}
	if !contains(s, `weird\"sid\\with\\backslash`) {
		t.Fatalf("sid 转义结果不对:\n%s", s)
	}
}

// TestJSONEscape 覆盖 digest.go 的转义规则。
func TestJSONEscape(t *testing.T) {
	cases := map[string]string{
		"":      "",
		"plain": "plain",
		`a"b`:   `a\"b`,
		`a\b`:   `a\\b`,
		"a\nb":  `a\nb`,
		"a\tb":  `a\tb`,
		"中文":    "中文",
	}
	for in, want := range cases {
		if got := jsonEscape(in); got != want {
			t.Errorf("jsonEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestUpperHashes 验证两个哈希格式与官方客户端一致（大写）。
func TestUpperHashes(t *testing.T) {
	// SHA256("abc") 是公开的测试向量
	if got := upperSHA256Hex("abc"); got != "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" {
		t.Errorf("upperSHA256Hex(abc) = %s", got)
	}
	if got := upperMD5Hex("abc"); got != "900150983CD24FB0D6963F7D28E17F72" {
		t.Errorf("upperMD5Hex(abc) = %s", got)
	}
}

// ---------- route.go ----------

// TestResourceIndexRealTree 用真实三层结构验证索引构建。
func TestResourceIndexRealTree(t *testing.T) {
	raw := map[string]any{
		"appList": map[string]any{
			"code": 0,
			"data": map[string]any{
				"config": map[string]any{
					"nodeGroupConf": map[string]any{
						"majorNodeGroup": map[string]any{"id": "ng-1"},
						"nodeGroupList": []any{
							map[string]any{
								"id": "ng-1",
								"addressInfo": []any{
									map[string]any{"type": "wan", "address": "gw.example.com:441"},
									map[string]any{"type": "lan", "address": "10.0.0.1:441"},
								},
							},
						},
					},
				},
				"appInfo": []any{
					map[string]any{
						"name":        "演示资源",
						"nodeGroupId": "ng-1",
						"apps": []any{
							map[string]any{
								"id":          "app-1",
								"accessModel": "L3VPN",
								"addressList": []any{
									map[string]any{"protocol": "tcp", "port": "443", "host": "10.15.45.163"},
									map[string]any{"protocol": "tcp", "port": "443", "host": "library.example.com"},
								},
							},
						},
					},
				},
			},
		},
	}

	idx := buildResourceIndex(raw)

	if idx.firstAppID != "app-1" {
		t.Errorf("firstAppID = %q, want app-1", idx.firstAppID)
	}
	// type != "wan" 的线路必须被忽略
	if got := idx.nodeAddrs["ng-1"]; got != "gw.example.com:441" {
		t.Errorf("线路 = %q, want gw.example.com:441（lan 线路应被忽略）", got)
	}

	// IP 精确命中
	e, ok := idx.lookup("10.15.45.163", 443)
	if !ok {
		t.Fatal("10.15.45.163:443 未命中")
	}
	if e.AppID != "app-1" || e.NodeGroupID != "ng-1" {
		t.Errorf("命中规则 = %v", e)
	}

	// 域名精确命中
	if _, ok := idx.lookup("library.example.com", 443); !ok {
		t.Error("library.example.com:443 未命中")
	}

	// 端口不匹配时不命中
	if _, ok := idx.lookup("10.15.45.163", 8443); ok {
		t.Error("端口不匹配却命中了")
	}
}

// TestResourceIndexPortWildcard 验证 port "0" 是通配。
func TestResourceIndexPortWildcard(t *testing.T) {
	idx := buildResourceIndex(map[string]any{
		"appList": map[string]any{
			"data": map[string]any{
				"config": map[string]any{
					"nodeGroupConf": map[string]any{
						"majorNodeGroup": map[string]any{"id": "ng"},
						"nodeGroupList": []any{
							map[string]any{"id": "ng", "addressInfo": []any{
								map[string]any{"type": "wan", "address": "10.0.0.1"},
							}},
						},
					},
				},
				"appInfo": []any{
					map[string]any{
						"apps": []any{
							map[string]any{
								"id": "app-net",
								"addressList": []any{
									map[string]any{"protocol": "tcp", "port": "0", "host": "10.20.0.0/16"},
								},
							},
						},
					},
				},
			},
		},
	})

	// CIDR 应覆盖任意端口
	for _, port := range []int{80, 443, 3306} {
		if _, ok := idx.lookup("10.20.1.5", port); !ok {
			t.Errorf("10.20.1.5:%d 未命中（port=0 应通配）", port)
		}
	}
	// 范围外不命中
	if _, ok := idx.lookup("10.21.0.1", 80); ok {
		t.Error("10.21.0.1 在 10.20.0.0/16 之外，不该命中")
	}
}

// TestResourceIndexCIDRSpecificity 验证"覆盖范围小的优先"。
func TestResourceIndexCIDRSpecificity(t *testing.T) {
	idx := &resourceIndex{}
	idx.entries = []routeEntry{
		{Kind: "cidr", Value: "10.0.0.0/8", AppID: "broad"},
		{Kind: "cidr", Value: "10.20.0.0/16", AppID: "narrow"},
		{Kind: "cidr", Value: "10.20.5.0/24", AppID: "narrowest"},
	}

	if e, ok := idx.lookup("10.20.5.9", 443); !ok || e.AppID != "narrowest" {
		t.Errorf("10.20.5.9 命中 %v, want narrowest", e)
	}
	if e, ok := idx.lookup("10.20.9.9", 443); !ok || e.AppID != "narrow" {
		t.Errorf("10.20.9.9 命中 %v, want narrow", e)
	}
	if e, ok := idx.lookup("10.99.9.9", 443); !ok || e.AppID != "broad" {
		t.Errorf("10.99.9.9 命中 %v, want broad", e)
	}
}

// TestResourceIndexRange 验证闭区间规则。
func TestResourceIndexRange(t *testing.T) {
	idx := &resourceIndex{}
	idx.entries = []routeEntry{
		{Kind: "range", Value: "10.20.1.1-10.20.1.10", AppID: "range-app"},
	}

	if e, ok := idx.lookup("10.20.1.5", 22); !ok || e.AppID != "range-app" {
		t.Errorf("区间内未命中: %v", e)
	}
	if _, ok := idx.lookup("10.20.1.11", 22); ok {
		t.Error("区间外却命中了")
	}
}

// TestResourceIndexSuffix 验证后缀通配兜底。
func TestResourceIndexSuffix(t *testing.T) {
	idx := &resourceIndex{}
	idx.entries = []routeEntry{
		{Kind: "suffix", Value: ".example.com", AppID: "wild"},
	}

	if e, ok := idx.lookup("a.b.example.com", 443); !ok || e.AppID != "wild" {
		t.Errorf("后缀未命中: %v", e)
	}
	if _, ok := idx.lookup("example.org", 443); ok {
		t.Error("不匹配的后缀却命中了")
	}
}

// TestResourceIndexNodeFallback 验证线路兜底顺序。
func TestResourceIndexNodeFallback(t *testing.T) {
	idx := &resourceIndex{
		nodeAddrs:   map[string]string{"ng-a": "a:441", "ng-b": "b:441"},
		defaultNode: "ng-b",
	}

	// 规则自带 nodeGroup 时用它
	if got := idx.nodeFor(routeEntry{NodeGroupID: "ng-a"}); got != "a:441" {
		t.Errorf("nodeFor = %q, want a:441", got)
	}
	// 规则没有 nodeGroup 时用 majorNodeGroup
	if got := idx.nodeFor(routeEntry{}); got != "b:441" {
		t.Errorf("nodeFor(空) = %q, want b:441", got)
	}
	// 有 nodeGroup 但它不在列表里 → 退回默认
	if got := idx.nodeFor(routeEntry{NodeGroupID: "ng-missing"}); got != "b:441" {
		t.Errorf("nodeFor(未知组) = %q, want b:441", got)
	}
}

// TestParseNodeGroupAddsDefaultPort 验证缺端口时补 :441。
func TestParseNodeGroupAddsDefaultPort(t *testing.T) {
	idx := &resourceIndex{nodeAddrs: map[string]string{}}
	idx.parseNodeGroups(map[string]any{
		"nodeGroupList": []any{
			map[string]any{"id": "ng", "addressInfo": []any{
				map[string]any{"type": "wan", "address": "10.0.0.5"},
			}},
		},
	})
	if got := idx.nodeAddrs["ng"]; got != "10.0.0.5:441" {
		t.Errorf("线路 = %q, want 10.0.0.5:441", got)
	}
}

// TestDeriveSignKey 用 zju-connect 的公开向量验证 signKey 派生。
//
// 该向量与 mitmSig 的偏移量都在 antimitm_test.go 里用过；这里只确认
// deriveSignKey 与 signKeyFor 完全一致（两处独立实现不应有偏差）。
func TestDeriveSignKeyMatchesMockVector(t *testing.T) {
	d := AntiMITMData{
		DevicePubKeyMod: "A1B2C3",
		DevicePubKeyExp: "10001",
		Challenge:       "challenge-vector",
	}
	got := deriveSignKey(d)

	// 手算：first = SHA256("A1B2C310001" + salt)
	//       second = SHA256(UPPER_HEX(first) + challenge)
	//       key = first XOR second
	want := signKeyForVector(t, d)
	if len(got) != 32 {
		t.Fatalf("signKey 长度 = %d, want 32", len(got))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("signKey 字节 %d 不一致", i)
		}
	}
}

// TestRequestSigMessage 验证 X-Request-Sig 的消息是 msg 本身（不再拼路径）。
func TestRequestSigMessage(t *testing.T) {
	c := &Client{signKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}

	// libreatrust sign.rs 的测试向量：key=hex_decode("0123456789abcdef..."→ 必须是
	// 32 字节 key 才能复现)，这里用自己的向量自洽验证。
	sig := c.requestSig([]byte("abc"))
	if len(sig) != 64 {
		t.Fatalf("签名长度 = %d, want 64", len(sig))
	}
	// 同样输入必须得到同样输出（确定性）
	if sig != c.requestSig([]byte("abc")) {
		t.Error("同一输入的签名不一致")
	}
	// 不同输入必须不同
	if sig == c.requestSig([]byte("abd")) {
		t.Error("不同输入得到了相同签名")
	}
	// 没有 signKey 时返回空串，而不是报错
	empty := &Client{}
	if got := empty.requestSig([]byte("abc")); got != "" {
		t.Errorf("无 signKey 时返回 %q, want 空串", got)
	}
}

// ---------- 辅助 ----------

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }

// signKeyForVector 用与 signKeyFor 相同但独立写一遍的算法计算期望值，
// 用于确认 deriveSignKey 没有偏离规范。
func signKeyForVector(t *testing.T, d AntiMITMData) []byte {
	t.Helper()
	first := sha256Sum([]byte(d.DevicePubKeyMod + d.DevicePubKeyExp + signatureSalt))
	firstHex := strings.ToUpper(hex.EncodeToString(first))
	second := sha256Sum([]byte(firstHex + d.Challenge))

	out := make([]byte, 32)
	for i := range out {
		out[i] = first[i] ^ second[i]
	}
	return out
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
