package atrust

// mockproc_test.go — 在测试里把 test/mock/atrust 这个 mock 网关作为**子进程**
// 拉起来，跑完即杀。
//
// 为什么要子进程而不是 import：
//   - test/mock/atrust 是 package main（它是给官方 aTrust 客户端对撞用的可执行
//     基准），没有可导出的 New/Start，无法被 import 进测试直接托管。
//   - 把它拆成 library 会改动这个**已冻结的测试基准**。本仓库的约定是"裁判员不
//     下场"——我们改客户端去对齐基准，不改基准去迁就客户端。
//
// 为什么测试要自己拉起而不是连外部进程：
//   - 一条命令可复现，不必先手动起 mock、也不必约定某个端口空着；
//   - 随机端口，不会和正在跑的 v5vpn mock 抢 8443。
//
// 这里刻意只做"启停与就绪探测"，不含任何协议断言——断言放在 e2e_mock_test.go，
// 让这份 harness 保持单一职责，也方便 UI E2E 之外的其它测试复用。

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// mockAddr 是已就绪 mock 的接入地址与清理函数。
type mockAddr struct {
	BaseURL string
	Cleanup func()
}

// startMock 构建 test/mock/atrust 并在随机端口拉起它，返回 https 接入地址。
//
// 构建产物缓存在 t.TempDir 之外（见下），因为 t.TempDir 会在测试结束删掉——
// 但我们要在测试运行期间保留 exe 与密钥目录。用独立 os.MkdirTemp，自己负责清理。
func startMock(t *testing.T) *mockAddr {
	t.Helper()

	exe := buildMockExe(t)
	dir := mkMockDataDir(t)
	addr := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, exe, "-addr", addr, "-dir", dir, "-v=false")
	// mock 的 stdout/stderr 是它自己的请求日志。失败时它比任何断言都有用，
	// 所以接到 buffer，只在测试失败时 dump。
	var logBuf syncBuffer
	cmd.Stdout = &logBuf
	cmd.Stderr = &logBuf

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("启动 mock 失败: %v", err)
	}

	cleanup := func() {
		// 先杀进程再删目录：进程还握着 requests.log 的文件句柄时，
		// Windows 上 RemoveAll 会失败。
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		_ = os.RemoveAll(dir)
	}

	if !waitReady(t, addr, 15*time.Second) {
		out := logBuf.String()
		cleanup()
		t.Fatalf("mock 在 %s 未就绪；mock 输出:\n%s", addr, out)
	}

	t.Cleanup(cleanup)
	return &mockAddr{BaseURL: "https://" + addr, Cleanup: cleanup}
}

// buildMockExe 用 go build 产出 mock 可执行文件。
//
// 从子包（internal/atrust）用 import path 构建是可行的——已实测——因为
// go build <pkg> 与当前工作目录无关，只要在该 module 内即可。
func buildMockExe(t *testing.T) string {
	t.Helper()

	buildDir, err := os.MkdirTemp("", "atrustmock-build-")
	if err != nil {
		t.Fatalf("建构建目录: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(buildDir) })

	out := filepath.Join(buildDir, "atrust-mock.test"+exeSuffix())
	cmd := exec.Command("go", "build", "-o", out, "github.com/hygkui/v5vpn-rea-client/test/mock/atrust")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("构建 mock 失败: %v\n%s", err, b)
	}
	return out
}

func mkMockDataDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "atrustmock-data-")
	if err != nil {
		t.Fatalf("建数据目录: %v", err)
	}
	return dir
}

// freePort 找一个当前空闲的 127.0.0.1 端口，返回 "127.0.0.1:port"。
//
// 关闭 listener 后把端口号交给 mock 去 bind，存在极小的竞态窗口；本机测试可接受。
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

// waitReady 轮询 TCP 连接，直到 mock 开始监听或超时。
func waitReady(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// syncBuffer 是并发安全的 bytes.Buffer 包装，供子进程日志用。
//
// os/exec 会从它自己的 goroutine 写，测试主 goroutine 读——裸 bytes.Buffer
// 会 data race，-race 下直接炸。
type syncBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return fmt.Sprintf("%s", b.data)
}
