package config

import (
	"os"
	"testing"
)

func TestLoadSettingXML(t *testing.T) {
	// Prefer the synthetic fixture (configs/setting.xml.example) so this
	// test runs everywhere, including CI. A real configs/setting.xml with
	// production credentials must never exist in the repo; if one is
	// present locally it takes precedence for manual verification.
	localPath := "../../configs/setting.xml.example"
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		localPath = "../../configs/setting.xml"
	}
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		localPath = SettingXMLFilename
	}
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		t.Skip("No setting.xml fixture found, skipping test")
	}

	cfg, err := LoadSettingXML(localPath)
	if err != nil {
		t.Fatalf("LoadSettingXML failed: %v", err)
	}

	if len(cfg.Gateways) == 0 {
		t.Errorf("Expected at least 1 gateway, got 0")
	}

	t.Logf("Loaded %d gateways, LastUseGateway=%q", len(cfg.Gateways), cfg.LastUseGateway)
	for _, gw := range cfg.Gateways {
		t.Logf("  Gateway: %s (%s:%d), Algo=%d, Users=%d", gw.Name, gw.IP, gw.Port, gw.Algo, len(gw.SavedAccounts))
		for _, u := range gw.SavedAccounts {
			t.Logf("    User: %s (password length=%d)", u.Username, len(u.Password))
			if u.Password == "" {
				t.Errorf("Expected decrypted password for user %s, got empty", u.Username)
			}
		}
	}
}

// Snapshot is what the service hands to the HTTP API and the tray menu, so
// mutating it must not reach back into the live config.
func TestSnapshotIsIndependent(t *testing.T) {
	cfg := &AppConfig{
		LastUseGateway: "gw-a",
		Gateways: []GatewayProfile{{
			Name:          "gw-a",
			IP:            "203.0.113.10",
			SavedAccounts: []UserAccount{{Username: "alice", Password: "secret"}},
		}},
	}

	snap := cfg.Snapshot()
	if snap == nil {
		t.Fatal("Snapshot returned nil for a non-nil config")
	}

	snap.LastUseGateway = "gw-b"
	snap.Gateways[0].Name = "renamed"
	snap.Gateways[0].SavedAccounts[0].Password = "leaked"

	if cfg.LastUseGateway != "gw-a" {
		t.Errorf("LastUseGateway leaked into the live config: %q", cfg.LastUseGateway)
	}
	if cfg.Gateways[0].Name != "gw-a" {
		t.Errorf("gateway name leaked into the live config: %q", cfg.Gateways[0].Name)
	}
	if cfg.Gateways[0].SavedAccounts[0].Password != "secret" {
		t.Errorf("saved account leaked into the live config: %q", cfg.Gateways[0].SavedAccounts[0].Password)
	}
	if snap.Gateways[0].IP != "203.0.113.10" {
		t.Errorf("snapshot lost unrelated fields: %q", snap.Gateways[0].IP)
	}

	var nilCfg *AppConfig
	if nilCfg.Snapshot() != nil {
		t.Error("Snapshot on a nil config should return nil")
	}
}
