package service

import (
	"strings"
	"testing"
)

func TestCheckForUpdatesUnknownVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}

	s := NewVPNService(nil)
	// No SetAppVersion call: the service must not fall back to a stale
	// hard-coded release; it should treat itself as older than any release.
	info := s.CheckForUpdates()
	if info == nil {
		t.Fatal("expected non-nil UpdateInfo")
	}
	if info.Error != "" {
		t.Fatalf("unexpected error: %s", info.Error)
	}
	if !info.HasUpdate {
		t.Errorf("expected HasUpdate = true for unknown version, got false (latest %s)", info.LatestVersion)
	}
	if !strings.HasPrefix(info.CurrentVersion, "v0.") {
		t.Errorf("unexpected fallback current version: %q", info.CurrentVersion)
	}
}
