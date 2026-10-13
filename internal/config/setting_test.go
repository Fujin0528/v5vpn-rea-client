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
