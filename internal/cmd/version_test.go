package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The self-updater matches mygo.json "version" against the GitHub release
// tag ("v" + version), while the UI and window title use AppVersion. If these
// drift, update checks break silently — so fail loudly here instead.
func TestAppVersionMatchesMygoJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "mygo.json"))
	if err != nil {
		t.Fatalf("read mygo.json: %v", err)
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("parse mygo.json: %v", err)
	}
	want := "v" + strings.TrimPrefix(strings.TrimSpace(meta.Version), "v")
	if AppVersion != want {
		t.Fatalf("AppVersion = %q, want %q (mygo.json version = %q); bump both together",
			AppVersion, want, meta.Version)
	}
}
