package service

import (
	"testing"
)

// TestLiveVPNServiceCheckForUpdates exercises the real GitHub release lookup.
// It deliberately makes no assumption about which version is current: the
// repository publishes new releases regularly, so a hard-coded "latest" value
// would fail on every release. Instead it asserts the self-consistent
// relationship between the reported latest version and HasUpdate.
func TestLiveVPNServiceCheckForUpdates(t *testing.T) {
	if testing.Short() {
		t.Skip("network integration test skipped in -short mode")
	}

	s := NewVPNService(nil)

	// 1. Checking against the reported latest version must not offer an update.
	s.SetAppVersion("v0.0.0")
	baseline := s.CheckForUpdates()
	if baseline == nil {
		t.Fatal("expected non-nil UpdateInfo")
	}
	if baseline.Error != "" {
		t.Fatalf("unexpected error: %s", baseline.Error)
	}
	if baseline.LatestVersion == "" {
		t.Fatal("expected non-empty LatestVersion")
	}

	s.SetAppVersion(baseline.LatestVersion)
	info := s.CheckForUpdates()
	if info == nil {
		t.Fatal("expected non-nil UpdateInfo")
	}
	t.Logf("Update check result for %s: HasUpdate=%v, LatestVersion=%s, Error=%s, ReleaseURL=%s",
		baseline.LatestVersion, info.HasUpdate, info.LatestVersion, info.Error, info.ReleaseURL)
	if info.Error != "" {
		t.Fatalf("unexpected error: %s", info.Error)
	}
	if info.HasUpdate {
		t.Errorf("for %s vs latest (%s), HasUpdate should be false",
			baseline.LatestVersion, info.LatestVersion)
	}

	// 2. An older version must be offered the latest release, with notes.
	s.SetAppVersion("v0.0.0")
	infoOld := s.CheckForUpdates()
	if infoOld == nil {
		t.Fatal("expected non-nil UpdateInfo")
	}
	t.Logf("Update check result for v0.0.0: HasUpdate=%v, LatestVersion=%s, Notes=%d chars",
		infoOld.HasUpdate, infoOld.LatestVersion, len(infoOld.ReleaseNotes))
	if infoOld.Error != "" {
		t.Fatalf("unexpected error: %s", infoOld.Error)
	}
	if !infoOld.HasUpdate {
		t.Errorf("for v0.0.0 vs latest (%s), HasUpdate should be true", infoOld.LatestVersion)
	}
	if infoOld.LatestVersion != baseline.LatestVersion {
		t.Errorf("LatestVersion drifted between checks: %s vs %s",
			infoOld.LatestVersion, baseline.LatestVersion)
	}
}
