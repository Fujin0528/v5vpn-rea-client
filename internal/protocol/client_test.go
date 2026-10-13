package protocol

import "testing"

// TestClientLoginGateway is an integration probe against a real
// LeadSec-compatible VPN gateway. Credentials are placeholders; provide
// real ones via GATEWAY_IP / GATEWAY_PORT / GATEWAY_USER / GATEWAY_PASSWORD
// environment variables to run. Skipped by default and under -short.
func TestClientLoginGateway(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	const (
		gwIP   = "203.0.113.10"
		gwPort = 443
		user   = "<username>"
		pass   = "<password>"
	)
	client := NewClient(gwIP, gwPort, 0, func(level, format string, args ...any) {
		t.Logf("[%s] %s", level, format)
	})

	v, err := client.Handshake()
	if err != nil {
		t.Skipf("Gateway unreachable, skipping: %v", err)
	}
	t.Logf("Gateway version: %s.%s", v.Major, v.Minor)

	integration, err := client.Login(user, pass, "")
	if err != nil {
		t.Skipf("Login not possible on placeholder credentials: %v", err)
	}
	defer client.Logout()

	if integration == nil {
		t.Fatalf("Integration info is nil")
	}
	t.Logf("Login successful! User: %s, Resources count: %d",
		integration.User.Name, len(integration.ResourceList.TCPUDPResources))
	for _, r := range integration.ResourceList.TCPUDPResources {
		t.Logf("  Resource: %s, IPs: %+v, Port: %s", r.Name, r.IPConfigs, r.Port)
	}
}
