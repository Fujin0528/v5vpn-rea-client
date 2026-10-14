package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// UpdateInfo holds details about the latest available release
type UpdateInfo struct {
	HasUpdate      bool   `json:"hasUpdate"`
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	ReleaseNotes   string `json:"releaseNotes"`
	ReleaseURL     string `json:"releaseURL"`
	DownloadURL    string `json:"downloadURL"`
	Error          string `json:"error,omitempty"`
}

type updateManifest struct {
	Version string `json:"version"`
	Notes   string `json:"notes"`
	Date    string `json:"date"`
	URL     string `json:"url"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Body    string `json:"body"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CompareVersions returns:
//
//	 1 if v1 > v2
//	-1 if v1 < v2
//	 0 if v1 == v2
//
// Version strings can have an optional leading 'v' or 'V' (e.g. "v0.1.1").
func CompareVersions(v1, v2 string) int {
	clean := func(v string) []int {
		v = strings.TrimSpace(v)
		v = strings.TrimPrefix(v, "v")
		v = strings.TrimPrefix(v, "V")
		parts := strings.Split(v, ".")
		nums := make([]int, 0, len(parts))
		for _, p := range parts {
			numStr := ""
			for _, r := range p {
				if r >= '0' && r <= '9' {
					numStr += string(r)
				} else {
					break
				}
			}
			n, _ := strconv.Atoi(numStr)
			nums = append(nums, n)
		}
		return nums
	}

	p1 := clean(v1)
	p2 := clean(v2)
	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(p1) {
			n1 = p1[i]
		}
		if i < len(p2) {
			n2 = p2[i]
		}
		if n1 > n2 {
			return 1
		}
		if n1 < n2 {
			return -1
		}
	}
	return 0
}

// CheckUpdateManifest fetches release manifest JSON from GitHub release downloads without API rate limits.
func CheckUpdateManifest(ctx context.Context, repo string, currentVersion string) (*UpdateInfo, error) {
	manifestName := fmt.Sprintf("update-%s-%s.json", runtime.GOOS, runtime.GOARCH)
	manifestURL := fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", repo, manifestName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v5vpn-rea-client/"+currentVersion)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest HTTP status: %d", resp.StatusCode)
	}

	var m updateManifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	if m.Version == "" {
		return nil, fmt.Errorf("invalid manifest: empty version")
	}

	latestVer := "v" + strings.TrimPrefix(strings.TrimSpace(m.Version), "v")
	hasUpdate := CompareVersions(latestVer, currentVersion) > 0

	releaseURL := fmt.Sprintf("https://github.com/%s/releases/tag/%s", repo, latestVer)
	downloadURL := m.URL
	if downloadURL == "" {
		downloadURL = releaseURL
	}

	return &UpdateInfo{
		HasUpdate:      hasUpdate,
		CurrentVersion: currentVersion,
		LatestVersion:  latestVer,
		ReleaseNotes:   strings.TrimSpace(m.Notes),
		ReleaseURL:     releaseURL,
		DownloadURL:    downloadURL,
	}, nil
}

// CheckGitHubReleaseRedirect checks the latest release by inspecting the 302 redirect of https://github.com/<repo>/releases/latest.
func CheckGitHubReleaseRedirect(ctx context.Context, repo string, currentVersion string) (*UpdateInfo, error) {
	reqURL := fmt.Sprintf("https://github.com/%s/releases/latest", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v5vpn-rea-client/"+currentVersion)

	// Custom client that doesn't follow redirects so we can inspect Location header
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, fmt.Errorf("no Location header in latest release redirect")
	}

	// loc is like "https://github.com/hygkui/v5vpn-rea-client/releases/tag/v0.1.1"
	tag := loc[strings.LastIndex(loc, "/")+1:]
	if tag == "" {
		return nil, fmt.Errorf("cannot parse tag from %s", loc)
	}

	hasUpdate := CompareVersions(tag, currentVersion) > 0
	return &UpdateInfo{
		HasUpdate:      hasUpdate,
		CurrentVersion: currentVersion,
		LatestVersion:  tag,
		ReleaseURL:     loc,
		DownloadURL:    loc,
	}, nil
}

// CheckUpdateFromURL fetches release info from a given GitHub API URL and compares it to currentVersion.
func CheckUpdateFromURL(ctx context.Context, apiURL string, currentVersion string) (*UpdateInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v5vpn-rea-client/"+currentVersion)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("网络请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API 返回状态码: %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析版本信息失败: %w", err)
	}

	latestVer := strings.TrimSpace(rel.TagName)
	hasUpdate := CompareVersions(latestVer, currentVersion) > 0

	downloadURL := rel.HTMLURL
	for _, asset := range rel.Assets {
		name := strings.ToLower(asset.Name)
		if strings.HasSuffix(name, ".exe") && (strings.Contains(name, "amd64") || strings.Contains(name, "setup")) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	return &UpdateInfo{
		HasUpdate:      hasUpdate,
		CurrentVersion: currentVersion,
		LatestVersion:  latestVer,
		ReleaseNotes:   strings.TrimSpace(rel.Body),
		ReleaseURL:     rel.HTMLURL,
		DownloadURL:    downloadURL,
	}, nil
}
