package main

// cmd/mock-atrust — 启动 aTrust 零信任网关模拟器。
//
// 代理执行 test/mock/atrust，为本地开发者提供与 cmd/mock-v5vpn 对称的直观命令入口：
//
//   go run ./cmd/mock-atrust -addr 127.0.0.1:8443
//
// 也可以直接在 test/mock/atrust 目录下 go run .

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	// 查找并调用当前进程对应的 go 工具运行 test/mock/atrust
	goBin := "go"
	args := append([]string{"run", "./test/mock/atrust"}, os.Args[1:]...)
	cmd := exec.Command(goBin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "运行 aTrust mock server 失败: %v\n", err)
		os.Exit(1)
	}
}
