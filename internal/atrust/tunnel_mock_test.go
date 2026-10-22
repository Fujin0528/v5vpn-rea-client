package atrust

// tunnel_mock_test.go — 用本地假网关验证整条 TCP 流式通道握手。
//
// 为什么值得写：帧顺序错了的现象是"连接建立但数据全乱"，与"协议理解
// 错误"很难区分。这个测试把**我们发出的字节序**固定下来，任何改动
// 破坏顺序都会立刻失败。
//
// 假网关只实现流式通道需要的那几帧，不实现控制面——用 SetSession /
// SetDeviceID 直接注入会话材料，绕过登录。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStreamGateway 是一个只认 TCP 流式通道的最小网关。
type fakeStreamGateway struct {
	ln     net.Listener
	target string // 期望收到的目标 host:port

	// serve() 在独立 goroutine 里跑，以下字段全部经 mu 读写。
	mu          sync.Mutex
	gotAuthJSON string
	gotTarget   []byte
	gotAppData  [][]byte
	closedWrite bool

	frameCh chan struct{} // 每收到一个数据帧发一次信号
	closeCh chan struct{} // 读到关闭帧后 close
}

// startFakeStreamGateway 起一个 TLS 监听，返回地址。
func startFakeStreamGateway(t *testing.T, target string) *fakeStreamGateway {
	t.Helper()

	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("启动假网关失败: %v", err)
	}

	g := &fakeStreamGateway{
		ln:      ln,
		target:  target,
		frameCh: make(chan struct{}, 32),
		closeCh: make(chan struct{}),
	}
	go g.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return g
}

func (g *fakeStreamGateway) addr() string { return g.ln.Addr().String() }

// authJSON 返回收到的认证 JSON（加锁拷贝）。
func (g *fakeStreamGateway) authJSON() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gotAuthJSON
}

// targetFrame 返回收到的目标地址帧（加锁拷贝）。
func (g *fakeStreamGateway) targetFrame() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]byte(nil), g.gotTarget...)
}

// appFrames 返回已收到的应用数据帧（加锁深拷贝）。
func (g *fakeStreamGateway) appFrames() [][]byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([][]byte, len(g.gotAppData))
	for i, f := range g.gotAppData {
		out[i] = append([]byte(nil), f...)
	}
	return out
}

// waitFrames 等到累计收到 n 个数据帧或超时。
func (g *fakeStreamGateway) waitFrames(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		g.mu.Lock()
		got := len(g.gotAppData)
		g.mu.Unlock()
		if got >= n {
			return true
		}
		select {
		case <-g.frameCh:
		case <-deadline:
			return false
		}
	}
}

// waitClosed 等到假网关读到关闭帧或超时。
func (g *fakeStreamGateway) waitClosed(timeout time.Duration) bool {
	select {
	case <-g.closeCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (g *fakeStreamGateway) serve() {
	conn, err := g.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 第一段：05 01 81 | 53 03 <BE16> <json> | 05 01 01 <ATYP> <addr> <BE16 port>
	var head [5]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return
	}
	if head != [5]byte{0x05, 0x01, 0x81, 0x53, 0x03} {
		return
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	auth := make([]byte, n)
	if _, err := io.ReadFull(conn, auth); err != nil {
		return
	}
	g.mu.Lock()
	g.gotAuthJSON = string(auth)
	g.mu.Unlock()

	// 目标地址帧：05 01 01 <ATYP> ...
	var tHead [4]byte
	if _, err := io.ReadFull(conn, tHead[:]); err != nil {
		return
	}
	target := append([]byte(nil), tHead[:]...)
	switch tHead[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		target = append(target, b...)
	case 0x03:
		var lb [1]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		target = append(target, lb[0])
		target = append(target, b...)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		target = append(target, b...)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	target = append(target, portBuf[:]...)
	g.mu.Lock()
	g.gotTarget = target
	g.mu.Unlock()

	// 回应：05 81 53 00 <BE16> <json>
	okJSON := []byte(`{"code":0,"data":{"deviceID":"FAKE"},"message":"OK"}`)
	resp := []byte{0x05, 0x81, 0x53, 0x00}
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(okJSON)))
	resp = append(resp, okJSON...)
	if _, err := conn.Write(resp); err != nil {
		return
	}

	// 等 4 字节空数据帧，然后回 05 00 表示连接成功
	var empty [4]byte
	if _, err := io.ReadFull(conn, empty[:]); err != nil {
		return
	}
	if empty != [4]byte{0x01, 0x00, 0x00, 0x00} {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 之后读应用数据帧，回显同样的内容
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		if hdr == [2]byte{0x01, 0x01} {
			var tail [2]byte
			if _, err := io.ReadFull(conn, tail[:]); err != nil {
				return
			}
			g.mu.Lock()
			g.closedWrite = true
			g.mu.Unlock()
			close(g.closeCh)
			return
		}
		if hdr != [2]byte{0x01, 0x00} {
			return
		}
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return
		}
		plen := binary.BigEndian.Uint16(lb[:])
		payload := make([]byte, plen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		g.mu.Lock()
		g.gotAppData = append(g.gotAppData, payload)
		g.mu.Unlock()
		select {
		case g.frameCh <- struct{}{}:
		default:
		}

		// 回显
		echo := []byte{0x01, 0x00}
		echo = binary.BigEndian.AppendUint16(echo, plen)
		echo = append(echo, payload...)
		if _, err := conn.Write(echo); err != nil {
			return
		}
	}
}

// newTunnelTestClient 构造一个已注入会话材料的 Client，线路指向假网关。
func newTunnelTestClient(t *testing.T, gwAddr string) *Client {
	t.Helper()

	c, err := NewClient("https://127.0.0.1:1", Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.SetSession("unit_uuid-sid")
	c.SetDeviceID("AABBCCDDEEFF00112233445566778899")
	c.SetUsername("user1@local")

	// 直接注入一条资源树，让 DialTCP 有线路可用。
	c.SetResources(map[string]any{
		"appList": map[string]any{
			"data": map[string]any{
				"config": map[string]any{
					"nodeGroupConf": map[string]any{
						"majorNodeGroup": map[string]any{"id": "ng"},
						"nodeGroupList": []any{
							map[string]any{"id": "ng", "addressInfo": []any{
								map[string]any{"type": "wan", "address": gwAddr},
							}},
						},
					},
				},
				"appInfo": []any{
					map[string]any{
						"apps": []any{
							map[string]any{
								"id": "app-1",
								"addressList": []any{
									map[string]any{"protocol": "tcp", "port": "443", "host": "10.15.45.163"},
								},
							},
						},
					},
				},
			},
		},
	})
	return c
}

// TestDialTCPHandshake 验证完整握手与双向数据。
func TestDialTCPHandshake(t *testing.T) {
	g := startFakeStreamGateway(t, "10.15.45.163:443")
	c := newTunnelTestClient(t, g.addr())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := c.DialTCP(ctx, "10.15.45.163", 443)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	// 认证 JSON 的关键字段
	for _, want := range []string{
		`"sid":"unit_uuid-sid"`,
		`"appId":"app-1"`,
		`"url":"tcp:10.15.45.163:443"`,
		`"deviceId":"AABBCCDDEEFF00112233445566778899"`,
		`"userName":"user1@local"`,
		`"destAddr":"10.15.45.163:443"`,
		`"process_trusted":"TRUSTED"`,
	} {
		if !strings.Contains(g.authJSON(), want) {
			t.Errorf("认证 JSON 缺少 %s\n实际: %s", want, g.authJSON())
		}
	}

	// 目标地址帧：05 01 01 01 0A 0F 2D A3 01 BB
	wantTarget := []byte{0x05, 0x01, 0x01, 0x01, 10, 15, 45, 163, 0x01, 0xBB}
	gotTarget := g.targetFrame()
	if len(gotTarget) != len(wantTarget) {
		t.Fatalf("目标帧 = % X, want % X", gotTarget, wantTarget)
	}
	for i := range wantTarget {
		if gotTarget[i] != wantTarget[i] {
			t.Fatalf("目标帧 = % X, want % X", gotTarget, wantTarget)
		}
	}

	// 双向数据
	msg := []byte("hello through the tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("回显 = %q, want %q", buf, msg)
	}

	// 关闭帧
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !g.waitClosed(5 * time.Second) {
		t.Error("关闭时没有发送 01 01 00 00 帧")
	}
}

// TestDialTCPNotManaged 验证没有可用线路时返回 ErrNotManaged。
func TestDialTCPNotManaged(t *testing.T) {
	c, err := NewClient("https://127.0.0.1:1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	c.SetSession("sid")
	c.SetDeviceID("AABBCCDDEEFF00112233445566778899")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 没有资源树 → 没有线路
	_, err = c.DialTCP(ctx, "10.0.0.1", 80)
	if err == nil {
		t.Fatal("没有线路却成功建立了隧道")
	}
	if !strings.Contains(err.Error(), "ErrNotManaged") &&
		!strings.Contains(err.Error(), "线路") {
		t.Errorf("错误信息应说明缺少线路: %v", err)
	}
}

// TestDialTCPMissingDeviceID 验证缺 deviceId 时明确报错。
//
// 这个检查很重要：deviceId 缺失时网关会把连接当成另一台设备，
// 表现为"连接成功但资源不可达"，比直接报错难查得多。
func TestDialTCPMissingDeviceID(t *testing.T) {
	c, err := NewClient("https://127.0.0.1:1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	c.SetSession("sid")
	// 故意不设 deviceID

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = c.DialTCP(ctx, "10.0.0.1", 80)
	if err == nil {
		t.Fatal("缺 deviceId 却成功了")
	}
	if !strings.Contains(err.Error(), "deviceId") {
		t.Errorf("错误信息应提到 deviceId: %v", err)
	}
}

// TestDialTCPMissingSession 验证未登录时的错误。
func TestDialTCPMissingSession(t *testing.T) {
	c, err := NewClient("https://127.0.0.1:1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = c.DialTCP(ctx, "10.0.0.1", 80)
	if err == nil {
		t.Fatal("未登录却成功了")
	}
	if !strings.Contains(err.Error(), "会话") && err != ErrNoSession {
		t.Errorf("错误应为 ErrNoSession: %v", err)
	}
}

// TestTCPConnWriteChunking 验证大于 64KB 的写入被正确分片。
func TestTCPConnWriteChunking(t *testing.T) {
	g := startFakeStreamGateway(t, "10.0.0.1:80")
	c := newTunnelTestClient(t, g.addr())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := c.DialTCP(ctx, "10.0.0.1", 80)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	// 70000 字节：必须分成 65535 + 4465 两帧
	payload := make([]byte, 70000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	if !g.waitFrames(2, 5*time.Second) {
		t.Fatalf("等待 2 个数据帧超时（当前 %d 帧）", len(g.appFrames()))
	}

	gotAppData := g.appFrames()
	if len(gotAppData) != 2 {
		t.Fatalf("收到 %d 个数据帧, want 2（长度分别为 %v）",
			len(gotAppData), frameLens(gotAppData))
	}
	if len(gotAppData[0]) != 65535 {
		t.Errorf("第一帧 = %d 字节, want 65535", len(gotAppData[0]))
	}
	if len(gotAppData[1]) != 70000-65535 {
		t.Errorf("第二帧 = %d 字节, want %d", len(gotAppData[1]), 70000-65535)
	}
}

func frameLens(frames [][]byte) []int {
	out := make([]int, len(frames))
	for i, f := range frames {
		out[i] = len(f)
	}
	return out
}

// selfSignedCert 生成一个本地测试用的自签证书。
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "atrust-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
