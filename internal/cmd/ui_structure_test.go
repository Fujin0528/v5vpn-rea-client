package main

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Guards the layout structure of the embedded UIs.
//
// A missing </div> in index.html nested #view-connected inside #view-login.
// Both views carry inline display:flex/none, so switching to the connected view
// hid the whole subtree: the app showed a blank black window after a successful
// login while nothing threw and no other test noticed. These tests assert the
// structural invariants directly, which a Go unit test can check cheaply.
//
// 现在有两套物理独立的前端（/v5vpn/ 与 /atrust/），每套都要过同样的
// 结构检查；TestUIsAreSeparated 再守住"分家"这条产品约束：各套界面只含
// 自己协议的能力，谁越界就失败。

var (
	divOpenRe  = regexp.MustCompile(`<div\b`)
	divCloseRe = regexp.MustCompile(`</div>`)
	// tagRe 用于按栈扫描标签；无闭合标签的元素不影响 <div> 深度统计，
	// 但保留完整标签形态以免属性里的 '>' 干扰。
	tagRe = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9-]*)([^>]*)>`)
)

// uiSuites 是两套前端各自的目录前缀（相对 uiEmbedFS 里的 ui/）。
//
// 用表驱动而不是给每套写一份测试：两套界面必须过同一组不变量，漏测其中
// 一套就是漏测一半的产品。
var uiSuites = []struct {
	name string
	dir  string
}{
	{"v5vpn", "ui/v5vpn/"},
	{"atrust", "ui/atrust/"},
}

func readUI(t *testing.T, name string) string {
	t.Helper()
	data, err := fs.ReadFile(uiEmbedFS, name)
	if err != nil {
		t.Fatalf("read embedded %s: %v", name, err)
	}
	return string(data)
}

// TestUIIndexHTMLDivsAreBalanced catches the class of defect that produced the
// post-login black screen: an unbalanced <div> lets the browser re-parent later
// sections into an element that is display:none.
func TestUIIndexHTMLDivsAreBalanced(t *testing.T) {
	for _, suite := range uiSuites {
		t.Run(suite.name, func(t *testing.T) {
			html := readUI(t, suite.dir+"index.html")
			if got, want := len(divOpenRe.FindAllString(html, -1)), len(divCloseRe.FindAllString(html, -1)); got != want {
				t.Fatalf("unbalanced <div> tags: %d opening, %d closing", got, want)
			}

			// Walk the tags and fail at the first depth-0 close or a non-zero
			// final depth, which is what re-parenting looks like.
			depth := 0
			for _, m := range tagRe.FindAllStringSubmatchIndex(html, -1) {
				name := html[m[4]:m[5]]
				if name != "div" {
					continue
				}
				if html[m[2]:m[3]] == "/" {
					depth--
					if depth < 0 {
						t.Fatal("index.html closes a <div> that was never opened")
					}
					continue
				}
				depth++
			}
			if depth != 0 {
				t.Fatalf("index.html leaves %d <div> element(s) unclosed", depth)
			}
		})
	}
}

// TestUIRootViewsAreSiblings is the precise invariant the black screen broke:
// #view-login and #view-connected must be siblings at the top level, never
// nested, because switching views toggles display on exactly these two nodes.
func TestUIRootViewsAreSiblings(t *testing.T) {
	for _, suite := range uiSuites {
		t.Run(suite.name, func(t *testing.T) {
			html := readUI(t, suite.dir+"index.html")

			loginIdx := strings.Index(html, `id="view-login"`)
			connectedIdx := strings.Index(html, `id="view-connected"`)
			if loginIdx < 0 || connectedIdx < 0 {
				t.Fatalf("root views missing (login=%d connected=%d)", loginIdx, connectedIdx)
			}
			if connectedIdx < loginIdx {
				t.Fatal("#view-connected appears before #view-login; expected the login view first")
			}

			// Count div depth at each view's opening tag. Both must sit at depth 1
			// (direct children of <body>), which also proves they are siblings.
			depths := map[string]int{}
			depth := 0
			for _, m := range tagRe.FindAllStringSubmatchIndex(html, -1) {
				name := html[m[4]:m[5]]
				if name != "div" {
					continue
				}
				closing := html[m[2]:m[3]] == "/"
				if closing {
					depth--
					continue
				}
				depth++
				tagStart := m[0]
				rest := html[tagStart:]
				switch {
				case strings.HasPrefix(rest, `<div id="view-login"`):
					depths["view-login"] = depth
				case strings.HasPrefix(rest, `<div id="view-connected"`):
					depths["view-connected"] = depth
				}
			}

			if depths["view-login"] != 1 {
				t.Fatalf("#view-login depth = %d, want 1 (direct child of <body>)", depths["view-login"])
			}
			if depths["view-connected"] != 1 {
				t.Fatalf("#view-connected depth = %d, want 1 — nested views hide the whole app "+
					"when the login view is display:none", depths["view-connected"])
			}
		})
	}
}

// TestUIViewIDsAreUnique keeps getElementById lookups unambiguous.
func TestUIViewIDsAreUnique(t *testing.T) {
	for _, suite := range uiSuites {
		t.Run(suite.name, func(t *testing.T) {
			html := readUI(t, suite.dir+"index.html")
			idRe := regexp.MustCompile(`id="([^"]+)"`)
			seen := map[string]int{}
			for _, m := range idRe.FindAllStringSubmatch(html, -1) {
				seen[m[1]]++
			}
			for id, n := range seen {
				if n > 1 {
					t.Errorf("duplicate id %q appears %d times; getElementById would return the first", id, n)
				}
			}
		})
	}
}

// TestAppJSReferencesExistingIDs catches renamed/removed elements: a lookup
// that returns null throws at the first property access, which surfaces to the
// user as a dead button rather than an error dialog.
//
// An id may live in one of two places: the static index.html, or an innerHTML
// template inside app.js itself — the V5VPN challenge modal rebuilds its body
// at runtime (captcha / certificate / SMS / password-change), so its
// "modal-*" ids exist only as template strings. A lookup is satisfied by
// either source; requiring both would forbid the modal, requiring only the
// static markup would forbid the lookup. Class selectors target nodes the
// script creates at runtime and are not checked.
func TestAppJSReferencesExistingIDs(t *testing.T) {
	for _, suite := range uiSuites {
		t.Run(suite.name, func(t *testing.T) {
			html := readUI(t, suite.dir+"index.html")
			js := readUI(t, suite.dir+"app.js")

			htmlIDs := map[string]bool{}
			for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
				htmlIDs[m[1]] = true
			}
			// Ids rendered by JS templates (the challenge modal body).
			jsIDs := map[string]bool{}
			for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(js, -1) {
				jsIDs[m[1]] = true
			}

			assertKnown := func(id string, how string) {
				if !htmlIDs[id] && !jsIDs[id] {
					t.Errorf("app.js %s '%s' but neither index.html nor an app.js template defines that id", how, id)
				}
			}

			getByID := regexp.MustCompile(`getElementById\('([^']+)'\)`)
			for _, m := range getByID.FindAllStringSubmatch(js, -1) {
				assertKnown(m[1], "calls getElementById")
			}

			idSelector := regexp.MustCompile(`querySelector(?:All)?\('#([A-Za-z0-9_-]+)'\)`)
			for _, m := range idSelector.FindAllStringSubmatch(js, -1) {
				assertKnown(m[1], "queries")
			}
		})
	}
}

// TestUIsAreSeparated 是本轮拆分的核心约束：两套前端不是"同一页面按协议
// 隐藏元素"，而是各写各的。按协议分家前，aTrust 界面里摆着加密算法下拉、
// 证书登录、图形验证码和改密入口 —— 这些点下去必然失败；反过来 V5VPN
// 界面也不该出现零信任的端点。
//
// 检查的是"本协议没有的能力不得出现在本套界面里"，而不是逐字相等：
// 注释里提一句另一套协议（说明"那套界面在别处"）是允许的，但可执行的
// 元素、端点、样式类都不许越界。切换链接是唯一允许的跨协议引用。
func TestUIsAreSeparated(t *testing.T) {
	cases := []struct {
		suite string
		dir   string
		// forbidden 在本套 UI 的三个文件里都必须零命中。
		forbidden []string
		// required 必须至少命中一次：缺了说明本套界面的关键能力被误删。
		required []string
	}{
		{
			suite: "atrust",
			dir:   "ui/atrust/",
			// aTrust 后端没有的能力：加密算法、证书登录、图形验证码、改密，
			// 以及 V5VPN 独占的端点。端点同时检查单/双引号两种写法，
			// 防止换一种引号风格就绕过这条约束。
			forbidden: []string{
				"new-gw-algo", "gw-algo-tag", "algo-tls", "algo-gm",
				"cert-panel", "import-cert",
				"verifycode",
				"password-change", "connected-change-pwd-btn",
				"'/api/login'", `"/api/login"`,
				"'/api/logout'", `"/api/logout"`,
				"'/api/status'", `"/api/status"`,
				"'/api/resources/refresh'", `"/api/resources/refresh"`,
				"'/api/certs'", `"/api/certs"`,
				"'/api/change-password'", `"/api/change-password"`,
			},
			required: []string{
				"'/api/atrust/login'", "'/api/atrust/logout'", "'/api/atrust/status'",
				"protocol === 'atrust'",
				`href="/v5vpn/"`,
			},
		},
		{
			suite: "v5vpn",
			dir:   "ui/v5vpn/",
			// V5VPN 后端没有的能力：零信任的认证链端点。算法、证书、验证码、
			// 改密是它自己的本事，必须留着（证书/验证码/改密现在都住在
			// 挑战模态里）。proto-atrust 的样式类也不该留下：那套胶囊只出现
			// 在 aTrust 界面的表格里。
			forbidden: []string{
				"'/api/atrust/login'", "'/api/atrust/logout'", "'/api/atrust/status'",
				"'/api/atrust/resources/refresh'",
				"proto-atrust",
			},
			required: []string{
				"'/api/login'", "'/api/logout'", "'/api/status'",
				"protocol !== 'atrust'",
				"new-gw-algo", "gw-algo-tag",
				"verifycode", "challenge-modal", "cert-login-btn",
				"connected-change-pwd-btn",
				`href="/atrust/"`,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.suite, func(t *testing.T) {
			var all strings.Builder
			for _, f := range []string{"index.html", "app.js", "style.css"} {
				all.WriteString(readUI(t, c.dir+f))
				all.WriteString("\n")
			}
			content := all.String()

			for _, tok := range c.forbidden {
				if strings.Contains(content, tok) {
					t.Errorf("%s 界面出现了不该属于它的 %q —— 两套前端按协议分开后，"+
						"跨协议的能力/端点必须留在各自那一套里", c.suite, tok)
				}
			}
			for _, tok := range c.required {
				if !strings.Contains(content, tok) {
					t.Errorf("%s 界面缺少 %q", c.suite, tok)
				}
			}
		})
	}
}

// TestUIsShareNoAssetFiles 防止 "先分家、再悄悄从另一套 load 一个共享脚本"
// 的退化：每套 index.html 只能引用同目录下的 style.css / app.js。
func TestUIsShareNoAssetFiles(t *testing.T) {
	for _, suite := range uiSuites {
		t.Run(suite.name, func(t *testing.T) {
			html := readUI(t, suite.dir+"index.html")
			if !strings.Contains(html, `href="style.css"`) {
				t.Error("index.html 未引用同目录 style.css")
			}
			if !strings.Contains(html, `src="app.js"`) {
				t.Error("index.html 未引用同目录 app.js")
			}
			// 引用另一套界面的资源（../v5vpn/、../atrust/）说明又耦合回去了。
			for _, bad := range []string{"../v5vpn/", "../atrust/"} {
				if strings.Contains(html, bad) {
					t.Errorf("index.html 引用了另一套界面的资源 %q", bad)
				}
			}
		})
	}
}

// TestUIViewsAreDistinct 捕捉"分家后两套页面又长成同一份"的退化：
// 两套 HTML 的视图骨架元素集合不应完全相同。这比逐字节比较温和 ——
// 共用品牌页脚、GitHub 链接是允许的 —— 但一旦谁把另一套的 index.html
// 整个拷过来，这里会红。
func TestUIViewsAreDistinct(t *testing.T) {
	idSet := func(dir string) map[string]bool {
		html := readUI(t, dir+"index.html")
		ids := map[string]bool{}
		for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
			ids[m[1]] = true
		}
		return ids
	}
	v5 := idSet("ui/v5vpn/")
	at := idSet("ui/atrust/")

	// 这些 ID 只该属于 V5VPN 一套；名称本身已经说明了归属。挑战模态与
	// 证书登录入口是网关驱动状态机的界面形态，aTrust 那套没有。
	v5Only := []string{"new-gw-algo", "challenge-modal", "cert-login-btn", "connected-change-pwd-btn"}
	for _, id := range v5Only {
		if !v5[id] {
			t.Errorf("V5VPN 界面缺少 %q", id)
		}
		if at[id] {
			t.Errorf("aTrust 界面出现了 V5VPN 专属的 %q", id)
		}
	}

	// 两套界面都必须有这些骨架节点，否则视图切换/登录流程会断。
	for _, id := range []string{"view-login", "view-connected", "gateway-select", "connect-btn", "disconnect-btn"} {
		if !v5[id] {
			t.Errorf("V5VPN 界面缺少骨架节点 %q", id)
		}
		if !at[id] {
			t.Errorf("aTrust 界面缺少骨架节点 %q", id)
		}
	}
}
