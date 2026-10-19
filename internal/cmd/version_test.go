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
		Name    string `json:"name"`
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

// AppName decides the per-user directory that holds setting.xml. mygo build
// takes it from mygo.json, developer builds get it from SetName; if the two
// diverge, the same user ends up with two config files that never see each
// other's edits.
func TestAppNameMatchesMygoJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "mygo.json"))
	if err != nil {
		t.Fatalf("read mygo.json: %v", err)
	}
	var meta struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("parse mygo.json: %v", err)
	}
	if AppName != meta.Name {
		t.Fatalf("AppName = %q, want %q (mygo.json name); bump both together", AppName, meta.Name)
	}
}
