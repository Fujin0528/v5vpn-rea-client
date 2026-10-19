package config

import (
	"os"
	"path/filepath"
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

// The loader must find the file in the per-user data directory once
// SetUserDataDir has been called, otherwise a GUI build that writes there
// would read defaults from the working directory on every start.
func TestLoadSettingXMLHonoursUserDataDir(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, filepath.Join(dir, SettingXMLFilename))

	previous := UserDataDir()
	SetUserDataDir(dir)
	t.Cleanup(func() { SetUserDataDir(previous) })

	// Run from a directory with no setting.xml so only the user data dir can
	// satisfy the lookup.
	t.Chdir(t.TempDir())

	cfg, err := LoadSettingXML("")
	if err != nil {
		t.Fatalf("LoadSettingXML did not consult the user data dir: %v", err)
	}
	if len(cfg.Gateways) == 0 {
		t.Fatal("loaded 0 gateways from the user data dir")
	}
	if cfg.SourcePath != filepath.Join(dir, SettingXMLFilename) {
		t.Errorf("SourcePath = %q, want the user data dir copy", cfg.SourcePath)
	}
}

// A portable deployment keeps setting.xml next to the executable. Saving must
// write back to that same file; landing in the user data dir instead creates a
// second copy that shadows the portable one on the next start.
func TestSaveSettingXMLWritesBackToSourcePath(t *testing.T) {
	portableDir := t.TempDir()
	portablePath := filepath.Join(portableDir, SettingXMLFilename)
	copyFixture(t, portablePath)

	userData := t.TempDir()
	previous := UserDataDir()
	SetUserDataDir(userData)
	t.Cleanup(func() { SetUserDataDir(previous) })

	cfg, err := LoadSettingXML(portablePath)
	if err != nil {
		t.Fatalf("LoadSettingXML(%q) failed: %v", portablePath, err)
	}

	cfg.LastUseGateway = "portable-edit"
	if err := cfg.SaveSettingXML(""); err != nil {
		t.Fatalf("SaveSettingXML failed: %v", err)
	}

	saved, err := LoadSettingXML(portablePath)
	if err != nil {
		t.Fatalf("reloading the portable file failed: %v", err)
	}
	if saved.LastUseGateway != "portable-edit" {
		t.Errorf("edit did not land in the portable file: %q", saved.LastUseGateway)
	}
	if _, err := os.Stat(filepath.Join(userData, SettingXMLFilename)); err == nil {
		t.Error("save also wrote a shadow copy into the user data dir")
	}
}

// Without a source file the save still has to land somewhere usable.
func TestSaveSettingXMLFallsBackToUserDataDir(t *testing.T) {
	userData := t.TempDir()
	previous := UserDataDir()
	SetUserDataDir(userData)
	t.Cleanup(func() { SetUserDataDir(previous) })

	cfg := &AppConfig{LastUseGateway: "fresh-install"}
	if err := cfg.SaveSettingXML(""); err != nil {
		t.Fatalf("SaveSettingXML failed: %v", err)
	}

	target := filepath.Join(userData, SettingXMLFilename)
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected %s to be created: %v", target, err)
	}

	saved, err := LoadSettingXML(target)
	if err != nil {
		t.Fatalf("reloading %s failed: %v", target, err)
	}
	if saved.LastUseGateway != "fresh-install" {
		t.Errorf("LastUseGateway = %q, want fresh-install", saved.LastUseGateway)
	}
}

// copyFixture places the synthetic setting.xml at the given path.
func copyFixture(t *testing.T, dst string) {
	t.Helper()
	data, err := os.ReadFile("../../configs/setting.xml.example")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
