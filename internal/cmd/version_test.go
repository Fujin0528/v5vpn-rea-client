package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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

// TestUIVersionBadgesMatchAppVersion guards the visible version badges in both
// frontends. 发版要同步五处版本号（见 docs/RELEASING.md），main.go 与
// mygo.json 已由上面两个测试拴住；界面这两份拷贝最容易漏改，单独守一道。
//
// 逐字面量比对而不是数出现次数：将来界面多一个徽标位置也不用改这个测试，
// 但任何一个徽标漂移都会红。
func TestUIVersionBadgesMatchAppVersion(t *testing.T) {
	versionRe := regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+`)
	for _, dir := range []string{"ui/v5vpn/", "ui/atrust/"} {
		html := readUI(t, dir+"index.html")
		all := versionRe.FindAllString(html, -1)
		if len(all) == 0 {
			t.Errorf("%sindex.html 没有任何版本徽标", dir)
			continue
		}
		for _, v := range all {
			if v != AppVersion {
				t.Errorf("%sindex.html 版本徽标 %s != AppVersion %s（发版时五处同步，见 docs/RELEASING.md）",
					dir, v, AppVersion)
			}
		}
	}
}
