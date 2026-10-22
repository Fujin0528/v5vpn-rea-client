package atrust

// password_test.go — 口令加密的回归测试。
//
// 这里的用例对应 §24.2 的实测结论：mock 网关用与官方客户端相同的参数
// 解出明文，尾部 rand 与下发的 antiReplayRand 一致。测试用**mock 的私钥**
// 生成密文再解回来，等价于"网关能解开我们提交的密文"。

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// newTestKey 生成一把 RSA-2048 私钥（与真实网关同规格）。
func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	return key
}

// decryptChunked 按官方分块规则把密文解回明文。
// 这是 mock 网关侧做的事，用它验证加密端与解密端的一致性。
func decryptChunked(t *testing.T, key *rsa.PrivateKey, cipherHex string) string {
	t.Helper()

	blockHexLen := key.Size() * 2 // 每块密文的 hex 长度
	if len(cipherHex)%blockHexLen != 0 {
		t.Fatalf("密文总长 %d 不是块长 %d 的整数倍", len(cipherHex), blockHexLen)
	}

	var out strings.Builder
	for i := 0; i < len(cipherHex); i += blockHexLen {
		block, err := hex.DecodeString(cipherHex[i : i+blockHexLen])
		if err != nil {
			t.Fatalf("第 %d 块不是合法 hex: %v", i/blockHexLen, err)
		}
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, key, block)
		if err != nil {
			t.Fatalf("第 %d 块解密失败: %v", i/blockHexLen, err)
		}
		out.Write(plain)
	}
	return out.String()
}

func TestEncryptPasswordMatchesOfficialFormat(t *testing.T) {
	key := newTestKey(t)

	// 用与官方一致的十进制指数字符串，走 ParsePublicKey 这条真实路径。
	modHex := hex.EncodeToString(key.N.Bytes())
	pub, err := ParsePublicKey(modHex, "65537")
	if err != nil {
		t.Fatalf("ParsePublicKey 失败: %v", err)
	}

	const (
		password = "hunter2"
		rand8    = "6f0f93570f8bd4d9" // 16 hex，与真实网关下发的长度一致
	)

	cipherHex, err := EncryptPassword(pub, password, rand8)
	if err != nil {
		t.Fatalf("EncryptPassword 失败: %v", err)
	}

	// 1. 长度：短口令应当只有一块。
	if want := key.Size() * 2; len(cipherHex) != want {
		t.Fatalf("密文长度 = %d, 期望 %d（单块）", len(cipherHex), want)
	}

	// 2. 全小写 hex —— 官方实现用小写，大写会让网关解不开（§5）。
	if cipherHex != strings.ToLower(cipherHex) {
		t.Error("密文不是全小写 hex")
	}

	// 3. 明文格式必须是 "<password>_<antiReplayRand>"。
	plain := decryptChunked(t, key, cipherHex)
	if want := password + "_" + rand8; plain != want {
		t.Fatalf("解密得到 %q, 期望 %q", plain, want)
	}
}

func TestEncryptPasswordChunksAt245(t *testing.T) {
	key := newTestKey(t)
	modHex := hex.EncodeToString(key.N.Bytes())
	pub, err := ParsePublicKey(modHex, "65537")
	if err != nil {
		t.Fatalf("ParsePublicKey 失败: %v", err)
	}

	// 构造一个刚好超过 245 字符的明文：password 长 245-16=229，
	// 加上 "_" 与 16 位 rand 正好 246，会切成 245 + 1 两块。
	password := strings.Repeat("a", 229)
	const rand8 = "0011223344556677"

	cipherHex, err := EncryptPassword(pub, password, rand8)
	if err != nil {
		t.Fatalf("EncryptPassword 失败: %v", err)
	}

	blocks := len(cipherHex) / (key.Size() * 2)
	if blocks != 2 {
		t.Fatalf("块数 = %d, 期望 2（明文 246 字节）", blocks)
	}

	plain := decryptChunked(t, key, cipherHex)
	if want := password + "_" + rand8; plain != want {
		t.Fatalf("跨块解密不一致（长度 %d vs %d）", len(plain), len(want))
	}
}

func TestEncryptPasswordEmptyPassword(t *testing.T) {
	// 空口令也要能走通：明文变成 "_<rand>"，仍有 17 字节。
	key := newTestKey(t)
	modHex := hex.EncodeToString(key.N.Bytes())
	pub, err := ParsePublicKey(modHex, "65537")
	if err != nil {
		t.Fatalf("ParsePublicKey 失败: %v", err)
	}

	cipherHex, err := EncryptPassword(pub, "", "aabbccddeeff0011")
	if err != nil {
		t.Fatalf("EncryptPassword 失败: %v", err)
	}
	if plain := decryptChunked(t, key, cipherHex); plain != "_aabbccddeeff0011" {
		t.Fatalf("解密得到 %q", plain)
	}
}

func TestParsePublicKeyRejectsBadInput(t *testing.T) {
	cases := []struct {
		name   string
		mod    string
		exp    string
		reason string
	}{
		{"空模数", "", "65537", "空"},
		{"空指数", "aabb", "", "空"},
		{"模数非 hex", "zzzz", "65537", "hex"},
		{"指数非数字", "aabbcc", "0x10001", "十进制"},
		{"模数为零", "00", "65537", "hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePublicKey(tc.mod, tc.exp); err == nil {
				t.Fatal("期望报错，实际成功")
			}
		})
	}
}

// TestParsePublicKeyExpIsDecimal 守护一个曾经踩过的坑：
// pubKeyExp 是十进制字符串 "65537"，按 hex 解析会得到 0x65537。
func TestParsePublicKeyExpIsDecimal(t *testing.T) {
	modHex := hex.EncodeToString(new(big.Int).SetInt64(1 << 30).Bytes())
	pub, err := ParsePublicKey(modHex, "65537")
	if err != nil {
		t.Fatalf("ParsePublicKey 失败: %v", err)
	}
	if pub.E != 65537 {
		t.Fatalf("E = %d, 期望 65537（十进制）", pub.E)
	}
}
