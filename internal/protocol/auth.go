package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// AuthKind classifies a rejected /vpn/user/auth/password result.
//
// Classification is based solely on the gateway result code. Only 0x100 means
// "password expired": SecUI.exe branches on that code alone when it opens the
// password-change view. A gateway can also answer 0x8000001A (ciphertext parse
// failure) with an "expired" sentence in msg, but the code still wins.
type AuthKind int

const (
	AuthKindOther AuthKind = iota
	AuthKindBadCredentials
	AuthKindPasswordExpired
	AuthKindVerifyCode
	// Certificate authentication rejections (0x103-0x108, 0x162). Codes come
	// from language.xml TAG 259-264 and 354; do not infer meaning from the
	// numeric order.
	AuthKindCertInvalid
	AuthKindCertUnavailable
	AuthKindCertExpired
	AuthKindCertRevoked
	AuthKindCertBadSignature
)

const (
	// codePasswordExpired is the only result that opens the password-change view.
	codePasswordExpired = 0x100
	// codeBadCredentials is a real username/password mismatch.
	codeBadCredentials = 0x101
	// codeDecryptFailed means the gateway could not decode the credential
	// fields (for example a value was not valid Base64, or an encode mode the
	// gateway does not expect). The original client still reports it as a
	// credential error.
	codeDecryptFailed      = 0x8000001A
	codeVerifyCode         = 0x66600011
	codeVerifyCodeAlt      = 0x80
	codeVerifyCodeMismatch = 0x80000021

	// Certificate authentication results.
	codeCertVerifyFailed = 0x103 // TAG 259 证书验证失败
	codeCertUnavailable  = 0x105 // TAG 261 证书认证不可用
	codeCertExpired      = 0x106 // TAG 262 证书已过期
	codeCertRevoked      = 0x107 // TAG 263 证书已被注销
	codeCertBadSignature = 0x108 // TAG 264 证书签名错误
	codeCertFailed       = 0x162 // TAG 354 证书认证失败（超期或验证失败）
)

// AuthError is a gateway authentication rejection with a stable kind.
type AuthError struct {
	Kind AuthKind
	Code string
	Msg  string
}

func (e *AuthError) Error() string {
	if e == nil {
		return "登录失败"
	}
	msg := e.Msg
	switch e.Kind {
	case AuthKindPasswordExpired:
		if msg == "" {
			msg = "账号口令已过期，需要修改密码"
		}
		// Keep a leading "口令过期" for readable logs; callers use
		// IsPasswordExpired rather than matching this text.
		return fmt.Sprintf("口令过期: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindBadCredentials:
		// Match the original client's error mapping: both a real mismatch and
		// a ciphertext parse failure are shown as an account/password error.
		if msg == "" || isResultCode(e.Code, codeBadCredentials) || isResultCode(e.Code, codeDecryptFailed) {
			msg = "用户名或密码错误"
		}
		return fmt.Sprintf("登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindVerifyCode:
		if msg == "" {
			msg = "需要图形验证码"
		}
		return fmt.Sprintf("登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertInvalid:
		if msg == "" {
			msg = "证书验证失败，请重新选择证书进行认证"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertUnavailable:
		if msg == "" {
			msg = "网关未启用以证书方式登录"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertExpired:
		if msg == "" {
			msg = "证书已过期，请重新选择证书进行认证"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertRevoked:
		if msg == "" {
			msg = "证书已被注销，请重新选择证书进行认证"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertBadSignature:
		if msg == "" {
			msg = "证书签名错误，请重新选择证书进行认证"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	default:
		if msg == "" {
			msg = "网关拒绝登录认证"
		}
		return fmt.Sprintf("登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	}
}

// IsPasswordExpired reports whether err is a password-change challenge.
func IsPasswordExpired(err error) bool {
	var authErr *AuthError
	return errors.As(err, &authErr) && authErr.Kind == AuthKindPasswordExpired
}

func displayCode(code string) string {
	if strings.TrimSpace(code) == "" {
		return "unknown"
	}
	return code
}

func newAuthError(code, msg string) *AuthError {
	return &AuthError{
		Kind: classifyAuth(code, msg),
		Code: code,
		Msg:  msg,
	}
}

func classifyAuth(code, _ string) AuthKind {
	n, ok := parseResultCode(code)
	if !ok {
		return AuthKindOther
	}
	switch n {
	case codePasswordExpired:
		return AuthKindPasswordExpired
	case codeBadCredentials, codeDecryptFailed:
		return AuthKindBadCredentials
	case codeVerifyCode, codeVerifyCodeAlt, codeVerifyCodeMismatch:
		return AuthKindVerifyCode
	case codeCertVerifyFailed, codeCertFailed:
		return AuthKindCertInvalid
	case codeCertUnavailable:
		return AuthKindCertUnavailable
	case codeCertExpired:
		return AuthKindCertExpired
	case codeCertRevoked:
		return AuthKindCertRevoked
	case codeCertBadSignature:
		return AuthKindCertBadSignature
	default:
		return AuthKindOther
	}
}

// authStep is the factor a gateway asks for next. The masks mirror the portal
// driver (jquery.sslvpn.js), which dispatches on the bits of each auth RESULT
// code: the lowest set factor bit names the step the client must submit next.
type authStep int

const (
	authStepUnknown authStep = iota
	authStepFailure
	authStepChallenge
	authStepPassword
	authStepCertificate
	authStepToken
	authStepSMC
	authStepPasswordChange
	authStepMachineInfo
	authStepRule
	authStepDone
)

// nextAuthStep decodes the next-factor mask of an auth result code. The
// precedence follows the portal driver exactly, because the masks overlap:
// 0x102, for instance, means "certificate" because 0x2 is tested before 0x180.
func nextAuthStep(code string) authStep {
	n, ok := parseResultCode(code)
	if !ok {
		return authStepUnknown
	}
	switch {
	case n&0x80000000 != 0:
		return authStepFailure
	case n == 0x00010001:
		return authStepChallenge
	case n&0x1 != 0:
		return authStepPassword
	case n&0x2 != 0:
		return authStepCertificate
	case n&0x4 != 0:
		return authStepToken
	case n&0x8 != 0:
		return authStepSMC
	case n&0x180 != 0:
		return authStepPasswordChange
	case n&0x270 != 0:
		return authStepMachineInfo
	case n&0x30000000 != 0:
		return authStepRule
	default:
		return authStepDone
	}
}

// IsCertAuthError reports whether err is a certificate-authentication
// rejection, so callers never offer a password change for it.
func IsCertAuthError(err error) bool {
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		return false
	}
	switch authErr.Kind {
	case AuthKindCertInvalid, AuthKindCertUnavailable, AuthKindCertExpired,
		AuthKindCertRevoked, AuthKindCertBadSignature:
		return true
	default:
		return false
	}
}

func isResultCode(code string, want uint64) bool {
	n, ok := parseResultCode(code)
	return ok && n == want
}

// parseResultCode reads a gateway RESULT code. Hex forms keep the 0x prefix;
// a pure decimal string is read as decimal so "256" and "0x100" agree.
func parseResultCode(code string) (uint64, bool) {
	s := strings.TrimSpace(code)
	if s == "" {
		return 0, false
	}
	base := 16
	if len(s) >= 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		s = s[2:]
	} else if !strings.ContainsAny(s, "abcdefABCDEF") {
		base = 10
	}
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func isSuccessCode(code string) bool {
	n, ok := parseResultCode(code)
	return ok && n == 0
}

// passwordAuthBody is the v2.0 password login form. Values are already
// standard Base64 (see base64AuthParam) and must not be URL-escaped: escaping
// '=' in the base64 tail makes the gateway decode garbage and return
// 0x8000001A.
func passwordAuthBody(encUser, encPwd, verifycode string) string {
	return fmt.Sprintf("username=%s&password=%s&encode=1&verifycode=%s", encUser, encPwd, verifycode)
}

// base64AuthParam encodes one login field the way SecLogin.dll does for
// encode=1. Its base64 routine (0x100240a0) is called with the CRLF wrap flag
// on for both the username and the password: standard alphabet with '='
// padding, a CRLF after every 76 output columns, and the final CRLF stripped
// again — except that when the full 3-byte-group part is a nonzero multiple of
// 76 columns (input length divisible by 57), the CRLF removed is the extra one
// the original loop wrote past the end, so one stray trailing CRLF survives.
// The gateway tolerates CRLF either way (the official client feeds it the same
// bytes for longer inputs), but we reproduce the original exactly.
func base64AuthParam(s string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(s))
	groups := len(s) / 3 * 4 // columns covering the full 3-byte groups
	if groups < 76 {
		return b64
	}
	var out strings.Builder
	out.Grow(len(b64) + len(b64)/76*2 + 2)
	for i := 0; i+76 <= groups; i += 76 {
		out.WriteString(b64[i : i+76])
		out.WriteString("\r\n")
	}
	if rest := groups % 76; rest != 0 || len(b64) > groups {
		// The tail line: remaining group columns and/or the '=' padding.
		out.WriteString(b64[groups-rest:])
	}
	return out.String()
}

// passwordChangeBody formats the request body for /vpn/user/auth/pwdchange.
// The original client posts both passwords as UTF-8 plaintext: its format
// string is "old_pwd=%s&new_pwd=%s", no encode parameter is sent, and the
// function never calls the base64 helper. The values still have to be
// percent-encoded: the request is sent as application/x-www-form-urlencoded,
// so a raw '&', '+' or '%' in a password is parsed as form syntax and the
// gateway stores a truncated or empty password.
func passwordChangeBody(oldPassword, newPassword string) string {
	return url.Values{
		"old_pwd": {oldPassword},
		"new_pwd": {newPassword},
	}.Encode()
}
