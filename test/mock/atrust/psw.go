package main

// psw.go — 处理 /passport/v1/auth/psw，并**解密**客户端提交的密文。
//
// 这是整个 mock 方案最有价值的环节。官方客户端会用 authConfig 下发的
// pubKey 加密 `password + "_" + antiReplayRand`（见 client.45d3faeb.js 的
// `const a = e + "_" + n`），然后按 245 字符分块、PKCS#1 v1.5 填充、
// 每块输出小写 hex、无分隔符拼接（old/jssdk/common.js 的 encrypt()）。
//
// 因此：**mock 能解出明文，就证明我们对 §5 的理解是对的**——
// 这是"官方实现 ↔ 我们的规范"的一次真正对撞，而不是自说自话。

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// pswReq 是 /passport/v1/auth/psw 的请求体（源码级证据：
// web/assets/useInitHelp-legacy.52821dc6.js 的
// `t={username:R.value+$,password:Pe(),rememberPwd:Ie(),graphCheckCode:n}`）。
type pswReq struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	RememberPwd    string `json:"rememberPwd"`
	GraphCheckCode string `json:"graphCheckCode"`
}

// decryptChunked 按「245 字符分块 + 小写 hex + PKCS#1 v1.5」逐块解密。
// 245 是 2048 位 RSA 单块可承载的最大明文字节数（256 - 11）。
func decryptChunked(priv *rsa.PrivateKey, cipherHex string) (string, error) {
	if cipherHex == "" {
		return "", fmt.Errorf("password 为空")
	}
	if len(cipherHex)%2 != 0 {
		return "", fmt.Errorf("hex 长度为奇数(%d)，不符合块结构", len(cipherHex))
	}
	raw, err := hex.DecodeString(strings.ToLower(cipherHex))
	if err != nil {
		return "", fmt.Errorf("hex 解码失败: %w", err)
	}
	// 每块密文 = RSA 模长（256 字节）
	k := priv.Size()
	if len(raw)%k != 0 {
		return "", fmt.Errorf("密文总长 %d 不是模长 %d 的整数倍（客户端可能未按 256 字节/块输出）", len(raw), k)
	}

	var sb strings.Builder
	for off := 0; off < len(raw); off += k {
		block := raw[off : off+k]
		// 必须用 PKCS#1 v1.5：这不是安全选择，而是**协议事实**——
		// 官方客户端用 jsbn 的 pkcs1pad2（old/libs/libs.js）加密，
		// 用 OAEP 会解不开。此处只处理本地 mock 的验证流量。
		pt, err := rsa.DecryptPKCS1v15(nil, priv, block) //nolint:staticcheck
		if err != nil {
			return "", fmt.Errorf("第 %d 块解密失败: %w", off/k+1, err)
		}
		sb.Write(pt)
	}
	return sb.String(), nil
}

// splitPasswordRand 拆出明文里的 `<password>_<antiReplayRand>` 结构。
// 用 LastIndex 切分：口令本身可能含下划线，而 antiReplayRand 恒为 16 hex。
func splitPasswordRand(plain string) (password, rand string, ok bool) {
	i := strings.LastIndex(plain, "_")
	if i < 0 {
		return "", "", false
	}
	return plain[:i], plain[i+1:], true
}

func (s *Server) handlePsw(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	var req pswReq
	if err := json.Unmarshal(body, &req); err != nil {
		s.replyErr(w, 75500004, "参数错误或缺少参数")
		return
	}

	// ---- 校验 csrfToken（验证客户端确实发送了这个头）----
	gotCSRF := r.Header.Get("x-csrf-token")
	s.mu.Lock()
	wantCSRF := s.csrfToken
	wantRand := s.antiReplayRand
	s.mu.Unlock()

	csrfOK := gotCSRF == wantCSRF
	if !csrfOK {
		s.logf("⚠ csrfToken 不匹配: got=%q want=%q", gotCSRF, wantCSRF)
	}

	// ---- 解密 ----
	plain, decErr := decryptChunked(s.rsaKey, req.Password)
	var password, randInPlain string
	var randOK bool
	if decErr == nil {
		password, randInPlain, randOK = splitPasswordRand(plain)
	}

	// ---- 打印一次完整的"对撞"结论 ----
	s.logf("──────── psw 解密结果 ────────")
	s.logf("  请求体:        username=%q rememberPwd=%q graphCheckCode=%q", req.Username, req.RememberPwd, req.GraphCheckCode)
	s.logf("  密文长度:      %d hex 字符（%d 块 × 512 hex）", len(req.Password), len(req.Password)/512)
	if decErr != nil {
		s.logf("  ❌ 解密失败:    %v", decErr)
	} else {
		s.logf("  ✅ 解密成功")
		s.logf("     明文:      %q", plain)
		if randOK {
			s.logf("     口令:      %q", password)
			s.logf("     尾部 rand: %q", randInPlain)
			if randInPlain == wantRand {
				s.logf("     ✅ 尾部 rand 与下发的 antiReplayRand 一致 —— §5 的明文格式得证")
			} else {
				s.logf("     ⚠ 尾部 rand(%q) ≠ 下发值(%q) —— 客户端可能复用了旧值", randInPlain, wantRand)
			}
		} else {
			s.logf("     ⚠ 明文里没有 '_' 分隔符 —— 与 §5 描述不符")
		}
	}
	s.logf("  csrfToken:     %v", csrfOK)
	s.logf("──────────────────────────────")

	// ---- 签发会话 ----
	sid := s.createSession(req.Username)
	s.mu.Lock()
	s.antiReplayRand = newHex(8) // 每次响应都换新（§20.3 的实测规则）
	s.mu.Unlock()

	// ★ 必须像真实网关一样下发会话 cookie。
	//
	// 渲染层的请求体里 token 字段是**恒为空字符串的常量**
	// （old/jssdk/common.js 的 createRequest）：
	//
	//	n = {addr: …, type:"web", guid: t, lang: getLanguage(), token: ""}
	//
	// 也就是说浏览器侧**从不显式传 sidTicket**：`setSidTicket()` 只把它写进
	// 内存/sessionStorage，真正的会话识别靠的是 cookie。抓包也印证了这一点
	// ——渲染层发出的 onlineInfo / authCheck 都没有 Sid-Ticket 头、没有 Cookie
	// （因为当时的 mock 从不发 Set-Cookie），而原生 agent 发的请求带 Sid-Ticket。
	//
	// 所以 mock 必须在 psw 响应里 Set-Cookie，否则 authCheck 就没法认出
	// "刚刚登录的是谁"，只能返回 session invalid —— 而这正是上一轮实测
	// 观察到的现象（详见 ATRUST_PROTOCOL_ANALYSIS.md §24.10）。
	//
	// cookie 名取 sidTicket：既是客户端 DATA_NAME 里的键名，也是 Go 客户端
	// 实际使用的头名（Sid-Ticket）对应物。
	setSidCookie(w, sid)

	// ★ nextService 必须严格取自客户端的分发表，否则整条登录链会「静默走完」。
	//
	// 客户端的分发表只有两个键（web/assets/common.844141aa.js 的 Me，
	// 与旧版 old/jssdk/api.js 的 _goToAuth 完全一致）：
	//
	//	const l = {"auth/authCheck": Ke, "auth/accessCheck": je};
	//	const u = l[nextService];
	//	if (u) { ...递归... }
	//	return (already || (!nextService && !onlineInfo.isOnline)) && (an(), Ee());
	//
	// 也就是说：**只有 nextService 为空、且 onlineInfo.isOnline 为假时**才会
	// 触发 an()（detectClient）+ Ee()（startClient，即启动原生 agent）。
	//
	// 早期 mock 这里写的是 "auth/checkAccess"——两个键都不匹配，于是
	// 客户端既不调 authCheck、也不调 accessCheck，直接 success(n, true)
	// 结束。表现就是：界面一直显示"登录中"，而 agent 的
	// /v1/service/status 始终返回 {"status":"logout"}，路由守卫据此把
	// 页面打回 login（详见 ATRUST_PROTOCOL_ANALYSIS.md §24.1）。
	//
	// 这里取 "auth/authCheck"：它是文档 §5.3 记录的真实网关取值，且
	// authCheck 之后客户端会调到 nextService 为空的分支，从而启动 agent。
	// 想测 accessCheck 分支可改成 "auth/accessCheck"。
	resp := map[string]any{
		"code":    0,
		"message": "成功",
		"data": map[string]any{
			"sidTicket":      sid,
			"currentService": "auth/psw",
			"nextService":    "auth/authCheck",
			"userName":       req.Username,
			"displayName":    req.Username,
			"isLogin":        1,
			"sid":            sid,
			"antiReplayRand": newHex(8),
			"csrfToken":      newUUID(),
		},
		"time": nowStr(),
	}
	s.replyJSON(w, resp)
}

// handleAuthCheck 对应 GET /passport/v1/auth/authCheck（§6.2「权限复核」）。
//
// 真实语义：网关据此复核"这个会话当前是否允许访问"，返回 ACL 数据。
// 客户端拿到响应后会递归回 Me()，用新的 nextService 决定下一步。
//
// ★ mock 这里故意把 nextService 置空，这是一个**受控偏离**：
// 真实网关在无 ACL 约束时通常也返回空 nextService（即"认证链结束"），
// 客户端随后走到 `!nextService && !onlineInfo.isOnline` 分支，执行
//
//	an() → detectClient()   （探测本机 agent 是否在跑）
//	Ee() → startClient()    （拉起 agent，把 sidTicket 交给它）
//
// 只有走完这一步，agent 的 /v1/service/status 才会从 logout 变成 online。
//
// 返回体里的 actionType/action/policyId/reason/sidTicket 是客户端
// Ge() 解析 acl data 时要求的列（缺字段会打
// `acl data column error: acl data [...] is not define`）：
//
//	["actionType","action","policyId","reason","sidTicket"].forEach(
//	  i => { !t[i] && n.push(i); e[i] = t[i] })
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.lookupSession(r)
	if !ok {
		// 真实网关靠 cookie 认会话；mock 在 psw 里已 Set-Cookie，
		// 走到这里说明客户端没带 cookie（例如 Cookie 被拦、或直接 curl 测试）。
		// 返回 session invalid 会让界面直接弹这个错误——那是上一轮实测踩过的坑。
		// 这里退化为"匿名通过"并打日志，保证认证链能继续推进到启动客户端。
		s.logf("⚠ authCheck 未带会话凭据（无 Sid-Ticket 头、无 cookie）——按匿名放行")
		s.replyJSON(w, map[string]any{
			"code":    0,
			"message": "成功",
			"data": map[string]any{
				"nextService":    "",
				"currentService": "auth/authCheck",
				"actionType":     "",
				"action":         "",
				"policyId":       "",
				"reason":         "",
				"taskId":         "",
			},
			"time": nowStr(),
		})
		return
	}
	s.logf("  authCheck：用户 %s 通过，nextService 置空以触发客户端拉起 agent", sess.Username)
	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data": map[string]any{
			// 认证链结束：客户端据此进入「启动客户端」分支
			"nextService":    "",
			"currentService": "auth/authCheck",
			"sidTicket":      sess.Sid,
			"actionType":     "",
			"action":         "",
			"policyId":       "",
			"reason":         "",
			"taskId":         "",
		},
		"time": nowStr(),
	})
}

// handleAccessCheck 对应 POST /passport/v1/auth/accessCheck（§6.2「访问复核」）。
//
// 与 authCheck 的区别：它以 POST 形式带业务字段，返回 ACL 明细。
// 客户端 je() 里对 ACL_PERMISSION_DENIED 有专门分支（会把 data.action
// 为 logout 时的 logoutUrl 存起来），所以这里必须给全 action 相关列，
// 否则 Ge() 会打 acl data column error。
func (s *Server) handleAccessCheck(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.lookupSession(r)
	if !ok {
		s.logf("⚠ accessCheck 未带会话凭据——按匿名放行")
		s.replyJSON(w, map[string]any{
			"code":    0,
			"message": "成功",
			"data": map[string]any{
				"nextService": "",
				"actionType":  "",
				"action":      "",
				"policyId":    "",
				"reason":      "",
				"taskId":      "",
			},
			"time": nowStr(),
		})
		return
	}
	s.logf("  accessCheck：用户 %s 通过", sess.Username)
	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		"data": map[string]any{
			"nextService": "",
			"sidTicket":   sess.Sid,
			"actionType":  "",
			"action":      "",
			"policyId":    "",
			"reason":      "",
			"taskId":      "",
		},
		"time": nowStr(),
	})
}

// replyErr 返回真实网关的失败体（code 75500000 是通用失败码，§20.3）。
func (s *Server) replyErr(w http.ResponseWriter, code int, msg string) {
	s.replyJSON(w, map[string]any{
		"code":    code,
		"message": msg,
		"data": map[string]any{
			"currentService":           "auth/psw",
			"nextService":              "auth/psw",
			"antiReplayRand":           newHex(8),
			"skipSecondaryAuthStatus":  0,
			"skipSecondaryAuthTimeout": 30,
		},
		"time": nowStr(),
	})
}
