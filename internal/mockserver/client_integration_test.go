package mockserver

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func TestMockServerIntegrationWithProtocolClient(t *testing.T) {
	srv, err := New(Config{
		Addr:        "127.0.0.1:0",
		Mode:        ModePwdCert,
		RequireCert: false,
		Verbose:     true,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", srv.httpSrv.TLSConfig)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	go srv.httpSrv.Serve(l)
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	client := protocol.NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("["+level+"] "+format, args...)
	})

	// 1. Handshake
	_, err = client.Handshake()
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// 2. Prepare mock client cert
	clientCert, _, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// 3. Two-factor login: Password + Certificate (Step 1 -> Code 2 -> Step 2 -> Code 0)
	resp, err := client.AuthPasswordWithCert(&clientCert, "admin", "admin123", "")
	if err != nil {
		t.Fatalf("AuthPasswordWithCert failed: %v", err)
	}
	if resp == nil {
		t.Fatalf("Expected non-nil response")
	}

	if client.SessionID == "" {
		t.Errorf("Expected client.SessionID to be set after 2FA login")
	}

	// 4. Get portal integration info
	info, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}
	if info.Session.ID == "" {
		t.Errorf("Expected non-empty Session ID, got %+v", info)
	}
	if info.User.Name != "admin" {
		t.Errorf("Expected User.Name admin, got %q", info.User.Name)
	}

	// 5. Logout
	err = client.Logout()
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}
}
