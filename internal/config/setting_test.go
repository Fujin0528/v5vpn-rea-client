package config

import (
	"os"
	"testing"
)

func TestLoadSettingXML(t *testing.T) {
	localPath := SettingXMLFilename
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		localPath = "../../../configs/setting.xml"
	}
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		t.Skip("Local setting.xml not found, skipping test")
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
