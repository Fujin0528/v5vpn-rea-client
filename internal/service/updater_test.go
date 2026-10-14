package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		{"v0.1.1", "v0.1.0", 1},
		{"v0.1.0", "v0.1.1", -1},
		{"v0.1.1", "v0.1.1", 0},
		{"0.1.1", "v0.1.1", 0},
		{"v0.1.1", "0.1.1", 0},
		{"v0.2.0", "v0.1.9", 1},
		{"v1.0.0", "v0.9.9", 1},
		{"v0.1.1.1", "v0.1.1", 1},
		{"v0.1.1", "v0.1.1.1", -1},
		{"v0.1.1-beta", "v0.1.0", 1},
	}

	for _, tt := range tests {
		got := CompareVersions(tt.v1, tt.v2)
		if got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
		}
	}
}

func TestCheckUpdateFromURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"tag_name": "v0.1.2",
			"html_url": "https://github.com/hygkui/v5vpn-rea-client/releases/tag/v0.1.2",
			"body": "Fixed update window blank bug",
			"assets": [
				{
					"name": "v5vpn-rea.Setup.0.1.2.amd64.exe",
					"browser_download_url": "https://github.com/hygkui/v5vpn-rea-client/releases/download/v0.1.2/v5vpn-rea.Setup.0.1.2.amd64.exe"
				}
			]
		}`))
	}))
	defer ts.Close()

	// Case 1: Newer version available
	info, err := CheckUpdateFromURL(context.Background(), ts.URL, "v0.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.HasUpdate {
		t.Errorf("expected hasUpdate = true")
	}
	if info.LatestVersion != "v0.1.2" {
		t.Errorf("latestVersion = %q, want v0.1.2", info.LatestVersion)
	}
	if info.DownloadURL != "https://github.com/hygkui/v5vpn-rea-client/releases/download/v0.1.2/v5vpn-rea.Setup.0.1.2.amd64.exe" {
		t.Errorf("unexpected download URL: %q", info.DownloadURL)
	}

	// Case 2: Already latest version
	infoSame, err := CheckUpdateFromURL(context.Background(), ts.URL, "v0.1.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if infoSame.HasUpdate {
		t.Errorf("expected hasUpdate = false for same version")
	}

	// Case 3: Newer current version
	infoNewer, err := CheckUpdateFromURL(context.Background(), ts.URL, "v0.1.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if infoNewer.HasUpdate {
		t.Errorf("expected hasUpdate = false when current is newer")
	}
}
