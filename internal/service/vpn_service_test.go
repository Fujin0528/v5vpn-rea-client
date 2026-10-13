package service

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestVPNService_LogoutNoDeadlock(t *testing.T) {
	var logged int32
	var statusChanged int32

	s := NewVPNService(func(msg string) {
		atomic.AddInt32(&logged, 1)
	})

	s.OnStatusChange = func(status string) {
		atomic.AddInt32(&statusChanged, 1)
	}

	// Test Logout when already disconnected
	done := make(chan bool, 1)
	go func() {
		ok, err := s.Logout()
		if err != nil {
			t.Errorf("Logout error: %v", err)
		}
		done <- ok
	}()

	select {
	case ok := <-done:
		if !ok {
			t.Errorf("expected Logout to return true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Logout deadlocked!")
	}

	st := s.GetStatus()
	if st["status"] != "Disconnected" {
		t.Errorf("expected status Disconnected, got %v", st["status"])
	}
}

func TestVPNService_ConcurrentLoggingAndStatus(t *testing.T) {
	s := NewVPNService(nil)

	// Launch concurrent log writers and status readers
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				s.Log("INFO", "worker %d iteration %d", id, j)
				_ = s.GetStatus()
				_ = s.GetLogs()
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	logs := s.GetLogs()
	if len(logs) == 0 {
		t.Errorf("expected logs to be recorded")
	}
}

func TestVPNService_LoginGateway2(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	var active atomic.Bool
	active.Store(true)
	defer func() {
		active.Store(false)
	}()

	s := NewVPNService(func(msg string) {
		if active.Load() {
			t.Log(msg)
		}
	})

	res, err := s.Login("demo-gateway", "<username>", "<password>", "", false, false)
	if err != nil {
		t.Skipf("Login not possible on placeholder credentials: %v", err)
	}

	if res["status"] != "Connected" {
		t.Fatalf("Expected status Connected, got %v", res["status"])
	}

	s.Logout()
	time.Sleep(50 * time.Millisecond)
}
