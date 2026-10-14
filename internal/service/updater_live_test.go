package service

import (
	"testing"
)

func TestLiveVPNServiceCheckForUpdates(t *testing.T) {
	s := NewVPNService(nil)
	s.SetAppVersion("v0.1.1")

	info := s.CheckForUpdates()
	if info == nil {
		t.Fatal("expected non-nil UpdateInfo")
	}

	t.Logf("Update check result for v0.1.1: HasUpdate=%v, LatestVersion=%s, CurrentVersion=%s, Error=%s, ReleaseURL=%s",
		info.HasUpdate, info.LatestVersion, info.CurrentVersion, info.Error, info.ReleaseURL)

	if info.Error != "" {
		t.Fatalf("unexpected error: %s", info.Error)
	}

	if info.HasUpdate {
		t.Errorf("for v0.1.1 vs latest (v0.1.1), HasUpdate should be false")
	}
	if info.LatestVersion != "v0.1.1" {
		t.Errorf("expected LatestVersion == v0.1.1, got %s", info.LatestVersion)
	}

	// Now test when current version is v0.1.0
	s.SetAppVersion("v0.1.0")
	infoOld := s.CheckForUpdates()
	t.Logf("Update check result for v0.1.0: HasUpdate=%v, LatestVersion=%s, CurrentVersion=%s, Notes=%d chars",
		infoOld.HasUpdate, infoOld.LatestVersion, infoOld.CurrentVersion, len(infoOld.ReleaseNotes))

	if !infoOld.HasUpdate {
		t.Errorf("for v0.1.0 vs latest (v0.1.1), HasUpdate should be true!")
	}
	if infoOld.LatestVersion != "v0.1.1" {
		t.Errorf("expected LatestVersion == v0.1.1, got %s", infoOld.LatestVersion)
	}
}
