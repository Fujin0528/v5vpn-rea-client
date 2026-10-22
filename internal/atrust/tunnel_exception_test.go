package atrust

// tunnel_exception_test.go — 隧道建立/运行失败时的行为。
//
// 正常路径在 tunnel_mock_test.go 里验。这里专挑**网关不按预期回话**的
// 情形：认证被拒、目标连不上、连接中途断开、收到畸形帧。
//
// 为什么值得单独写：这些分支的错误处理最容易写成"吞掉错误、连接保持
// 打开"，现象是网页一直转圈而不是报错。测试断言两件事——
//  1. 返回的 error 说明**发生了什么**（不是空错误，也不是超时）
//  2. 失败后底层连接确实被关掉了

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptedGateway 接受一条连接，按 handler 的剧本回应。
type scriptedGateway struct {
	ln net.Listener
}

// startScriptedGateway 起一个 TLS 监听。handler 拿到已完成 TLS 握手的
// 连接，自己决定读什么、回什么。
func startScriptedGateway(t *testing.T, handler func(conn net.Conn)) *scriptedGateway {
	t.Helper()

	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("启动假网关失败: %v", err)
	}

	g := &scriptedGateway{ln: ln}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		handler(conn)
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return g
}

func (g *scriptedGateway) addr() string { return g.ln.Addr().String() }

// readHandshake 把客户端发来的建立帧读干净，供 handler 使用。
//
// 返回值只用于"读到哪儿了"，正常情况下 handler 不关心内容。
func readHandshake(conn net.Conn) error {
	var head [5]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return err
	}
	auth := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, auth); err != nil {
		return err
	}

	// 目标地址帧：05 01 01 <ATYP> ...
	var tHead [4]byte
	if _, err := io.ReadFull(conn, tHead[:]); err != nil {
		return err
	}
	switch tHead[3] {
	case 0x01:
		_, err := io.ReadFull(conn, make([]byte, 4+2))
		return err
	case 0x03:
		var lb [1]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, int(lb[0])+2))
		return err
	case 0x04:
		_, err := io.ReadFull(conn, make([]byte, 16+2))
		return err
	}
	return nil
}

// sFrame 构造一个 53 00 <len> <payload>。
func sFrame(payload string) []byte {
	out := []byte{0x05, 0x81, 0x53, 0x00}
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
	return append(out, payload...)
}

// newClientForGateway 造一个会话材料齐全、线路指向 gwAddr 的客户端。
func newClientForGateway(t *testing.T, gwAddr string) *Client {
	t.Helper()

	c, err := NewClient("https://127.0.0.1:1", Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.SetSession("sid-for-test")
	c.SetDeviceID("AABBCCDDEEFF00112233445566778899")
	c.SetUsername("u@local")
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
					map[string]any{"apps": []any{
						map[string]any{"id": "app-1", "addressList": []any{
							map[string]any{"protocol": "tcp", "port": "443", "host": "10.0.0.1"},
						}},
					}},
				},
			},
		},
	})
	return c
}

// dialWithTimeout 用较短的超时拨号，避免失败用例挂到 30 秒。
func dialWithTimeout(t *testing.T, c *Client) (*TCPConn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c.DialTCP(ctx, "10.0.0.1", 443)
}

// TestTunnelAuthRejected 验证认证被拒时返回网关给的原因。
//
// 吞掉这条错误会让调用方以为连接建好了，然后在第一次读时拿到 EOF——
// 用户看到的是"连上了但没反应"。
func TestTunnelAuthRejected(t *testing.T) {
	g := startScriptedGateway(t, func(conn net.Conn) {
		if err := readHandshake(conn); err != nil {
			return
		}
		_, _ = conn.Write(sFrame(`{"code":2001,"message":"session expired"}`))
	})

	c := newClientForGateway(t, g.addr())
	conn, err := dialWithTimeout(t, c)
	if err == nil {
		conn.Close()
		t.Fatal("认证被拒却建连成功")
	}
	if !strings.Contains(err.Error(), "认证被拒绝") {
		t.Errorf("错误应说明认证被拒: %v", err)
	}
	// 网关给出的原因必须带出来，否则排查时无从下手。
	if !strings.Contains(err.Error(), "session expired") {
		t.Errorf("错误里丢了网关的原因: %v", err)
	}
}

// TestTunnelConnectStatusCodes 逐个验证 05 <status> 的失败码。
//
// 这些码直接对应"用户该怎么处理"：
// 0x05 是目标没开服务（改配置），0x02 是策略不允许（找管理员），
// 0x03/0x04 是网络问题（重试）。混成一句话会让人白折腾。
func TestTunnelConnectStatusCodes(t *testing.T) {
	cases := []struct {
		status byte
		want   string
	}{
		{0x01, "连接失败"},
		{0x02, "不被允许"},
		{0x03, "网络不可达"},
		{0x04, "主机不可达"},
		{0x05, "连接被拒绝"},
		{0x06, "TTL 到期"},
		{0x07, "不支持该命令"},
		{0x08, "不支持的地址类型"},
		{0x7F, "状态 0x7F"}, // 未文档化：仍要带出原始码
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			g := startScriptedGateway(t, func(conn net.Conn) {
				if err := readHandshake(conn); err != nil {
					return
				}
				if _, err := conn.Write(sFrame(`{"code":0,"message":"OK"}`)); err != nil {
					return
				}
				// 吃掉那个 4 字节空数据帧，再回状态。
				var empty [4]byte
				if _, err := io.ReadFull(conn, empty[:]); err != nil {
					return
				}
				_, _ = conn.Write([]byte{0x05, tc.status})
			})

			c := newClientForGateway(t, g.addr())
			conn, err := dialWithTimeout(t, c)
			if err == nil {
				conn.Close()
				t.Fatalf("状态 0x%02X 却建连成功", tc.status)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("状态 0x%02X 的错误 = %q，应包含 %q", tc.status, err, tc.want)
			}
		})
	}
}

// TestTunnelConnectStatusSuccess 确认 05 00 被当作成功。
//
// 与上面一组对照：如果成功码也被判失败，那组测试会全部"通过"而实际全错。
func TestTunnelConnectStatusSuccess(t *testing.T) {
	g := startScriptedGateway(t, func(conn net.Conn) {
		if err := readHandshake(conn); err != nil {
			return
		}
		if _, err := conn.Write(sFrame(`{"code":0,"message":"OK"}`)); err != nil {
			return
		}
		var empty [4]byte
		if _, err := io.ReadFull(conn, empty[:]); err != nil {
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x00})
		// 保持连接，等客户端自己关。
		_, _ = io.Copy(io.Discard, conn)
	})

	c := newClientForGateway(t, g.addr())
	conn, err := dialWithTimeout(t, c)
	if err != nil {
		t.Fatalf("05 00 应表示成功，却报错: %v", err)
	}
	_ = conn.Close()
}

// TestTunnelUnexpectedFrame 验证认证阶段收到无法解析的帧时报错。
//
// 静默跳过会破坏后续帧对齐——之后读到的每一个长度字段都是错的。
func TestTunnelUnexpectedFrame(t *testing.T) {
	g := startScriptedGateway(t, func(conn net.Conn) {
		if err := readHandshake(conn); err != nil {
			return
		}
		_, _ = conn.Write([]byte{0xDE, 0xAD})
	})

	c := newClientForGateway(t, g.addr())
	conn, err := dialWithTimeout(t, c)
	if err == nil {
		conn.Close()
		t.Fatal("收到畸形帧却建连成功")
	}
	if !strings.Contains(err.Error(), "意外帧") {
		t.Errorf("错误应指出收到了意外帧: %v", err)
	}
}

// TestTunnelGatewayClosesEarly 验证网关在握手阶段直接断开。
//
// 真实场景：441 端口没有服务、或中间设备重置连接。这里假网关接受 TCP
// 后立刻关闭，因此 TLS 握手本身就失败——错误必须指向"连不上数据面线路"，
// 而不是被误判成认证失败或 deviceId 缺失。
func TestTunnelGatewayClosesEarly(t *testing.T) {
	g := startScriptedGateway(t, func(conn net.Conn) {
		// 什么都不回，直接关（defer 里关）。
	})

	c := newClientForGateway(t, g.addr())
	conn, err := dialWithTimeout(t, c)
	if err == nil {
		conn.Close()
		t.Fatal("网关直接断开却建连成功")
	}
	if !strings.Contains(err.Error(), "数据面线路") {
		t.Errorf("错误应指向数据面线路: %v", err)
	}
	// 不能把它误判成会话/凭据问题——那会把排查方向带偏。
	if strings.Contains(err.Error(), "认证被拒绝") || strings.Contains(err.Error(), "deviceId") {
		t.Errorf("连接失败被误判成认证问题: %v", err)
	}
}

// TestTunnelDropMidStream 验证连接建立后网关断开，Read 返回错误。
//
// 这是最容易被写成死循环的地方：Read 拿到 EOF 必须原样返回，
// 而不是当作"暂时没数据"继续转。
func TestTunnelDropMidStream(t *testing.T) {
	g := startScriptedGateway(t, func(conn net.Conn) {
		if err := readHandshake(conn); err != nil {
			return
		}
		if _, err := conn.Write(sFrame(`{"code":0,"message":"OK"}`)); err != nil {
			return
		}
		var empty [4]byte
		if _, err := io.ReadFull(conn, empty[:]); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
		// 给一段数据，再断开。
		echo := []byte{0x01, 0x00, 0x00, 0x05}
		echo = append(echo, []byte("last!")...)
		_, _ = conn.Write(echo)
	})

	c := newClientForGateway(t, g.addr())
	conn, err := dialWithTimeout(t, c)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("断开前的数据应当可读: %v", err)
	}
	if string(buf) != "last!" {
		t.Errorf("数据 = %q, want last!", buf)
	}

	// 之后必须拿到错误，且不能是读超时（那说明它在傻等）。
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("网关已断开，Read 却返回了数据")
	}
	var ne net.Error
	if ok := asNetError(err, &ne); ok && ne.Timeout() {
		t.Fatal("网关已断开，Read 却挂到超时")
	}
}

// TestTunnelRemoteCloseFrame 验证收到 01 01 30 30 时 Read 返回 EOF。
//
// "30 30" 是网关侧的正常关闭信号。把它当成普通控制帧忽略掉，
// 上层就会一直读下去。
func TestTunnelRemoteCloseFrame(t *testing.T) {
	g := startScriptedGateway(t, func(conn net.Conn) {
		if err := readHandshake(conn); err != nil {
			return
		}
		if _, err := conn.Write(sFrame(`{"code":0,"message":"OK"}`)); err != nil {
			return
		}
		var empty [4]byte
		if _, err := io.ReadFull(conn, empty[:]); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
		_, _ = conn.Write([]byte{0x01, 0x01, 0x30, 0x30})
		time.Sleep(200 * time.Millisecond)
	})

	c := newClientForGateway(t, g.addr())
	conn, err := dialWithTimeout(t, c)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err != io.EOF {
		t.Errorf("收到关闭帧后 Read = %v, want io.EOF", err)
	}
}

// TestTunnelWriteAfterClose 验证关闭后写入返回错误而不是静默成功。
func TestTunnelWriteAfterClose(t *testing.T) {
	g := startScriptedGateway(t, func(conn net.Conn) {
		if err := readHandshake(conn); err != nil {
			return
		}
		if _, err := conn.Write(sFrame(`{"code":0,"message":"OK"}`)); err != nil {
			return
		}
		var empty [4]byte
		if _, err := io.ReadFull(conn, empty[:]); err != nil {
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x00})
		_, _ = io.Copy(io.Discard, conn)
	})

	c := newClientForGateway(t, g.addr())
	conn, err := dialWithTimeout(t, c)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	_ = conn.Close()

	if _, err := conn.Write([]byte("x")); err == nil {
		t.Error("关闭后写入返回了 nil 错误")
	}
	// 重复关闭必须安全（defer + 显式关闭是常见写法）。
	if err := conn.Close(); err != nil {
		t.Errorf("重复 Close 返回错误: %v", err)
	}
}

// asNetError 是 errors.As 的薄封装，避免与其它测试文件的 import 冲突。
func asNetError(err error, target *net.Error) bool {
	ne, ok := err.(net.Error)
	if ok {
		*target = ne
	}
	return ok
}
