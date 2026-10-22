package main

// antimitm_test.go — 锁定两道反中间人校验的计算结果。
//
// 测试向量取自 Mythologyli/zju-connect 的公开测试（client/atrust/auth/
// tls_test.go）。用别人的向量而不是自造向量，是为了证明我们的实现与
// 一份独立的开源实现逐字节一致——自造向量只能证明自己和自己一致。

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// zju-connect tls_test.go 的固定向量。
const (
	vecPubMod  = "A1B2C3"
	vecPubExp  = "10001"
	vecChal    = "challenge-vector"
	vecEncChal = "E4E065E124F3E6FA5B5125745170A7EE97342BB9E9AE2FF7F523FF5872B9541E"
	vecSig     = "50F004A1D13224483296CD1B8C64AF9E0CE8005E7E58EA056593A8BAAB2D57A8"
	vecRaw     = `{"enable":1,"antiMITMRequest":false,"devicePubKeyMod":"A1B2C3","devicePubKeyExp":"10001","rsaCert":"CERT","sm2encCert":"SM","challenge":"challenge-vector","encryptedChallenge":"E4E065E124F3E6FA5B5125745170A7EE97342BB9E9AE2FF7F523FF5872B9541E","ticket":"ticket","mitmSig":"50f004a1d13224483296cd1b8c64af9e0ce8005e7e58ea056593a8baab2d57a8"}`
)

func TestEncryptedChallengeVector(t *testing.T) {
	got := computeEncryptedChallenge(vecPubMod, vecPubExp, vecChal)
	if got != vecEncChal {
		t.Fatalf("encryptedChallenge\n got %s\nwant %s", got, vecEncChal)
	}
}

func TestMitmSigVector(t *testing.T) {
	got, err := computeMitmSig(vecPubMod, vecPubExp, vecChal, []byte(vecRaw))
	if err != nil {
		t.Fatal(err)
	}
	if got != vecSig {
		t.Fatalf("mitmSig\n got %s\nwant %s", got, vecSig)
	}
}

// TestFillAntiMITMIsSelfConsistent 验证「填好之后能自洽地重新验证通过」。
//
// 这条比前两条更接近客户端的真实行为：客户端拿到的是**已填好**的报文，
// 它要在这种状态下算出同样的签名。如果 origin 没有排除 mitmSig，
// 这一步会失败。
func TestFillAntiMITMIsSelfConsistent(t *testing.T) {
	d := antiMITMData{
		Enable:          1,
		DevicePubKeyMod: vecPubMod,
		DevicePubKeyExp: vecPubExp,
		RSACert:         "CERT",
		SM2EncCert:      "SM",
		Challenge:       vecChal,
		Ticket:          "ticket",
	}
	if err := fillAntiMITM(&d); err != nil {
		t.Fatal(err)
	}
	if d.EncryptedChallenge != vecEncChal {
		t.Fatalf("encryptedChallenge = %s", d.EncryptedChallenge)
	}
	if d.MitmSig != vecSig {
		t.Fatalf("mitmSig = %s", d.MitmSig)
	}

	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	again, err := computeMitmSig(d.DevicePubKeyMod, d.DevicePubKeyExp, d.Challenge, raw)
	if err != nil {
		t.Fatal(err)
	}
	if again != d.MitmSig {
		t.Fatalf("填回 mitmSig 后重算不一致: %s vs %s", again, d.MitmSig)
	}
}

// TestFillAntiMITMRejectsIncomplete 缺材料时宁可报错，也不下发必然被拒的值。
func TestFillAntiMITMRejectsIncomplete(t *testing.T) {
	if err := fillAntiMITM(&antiMITMData{DevicePubKeyExp: vecPubExp}); err == nil {
		t.Fatal("缺 challenge 应当报错")
	}
}

// TestMitmOriginSkipsSignature 锁定「mitmSig 不在 origin 里」这个前提。
func TestMitmOriginSkipsSignature(t *testing.T) {
	withSig := []byte(`{"challenge":"c","mitmSig":"AAAA"}`)
	withoutSig := []byte(`{"challenge":"c"}`)

	a, err := mitmOriginString(withSig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mitmOriginString(withoutSig)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("mitmSig 影响了 origin: %q vs %q", a, b)
	}
	if a != "challenge:c" {
		t.Fatalf("origin = %q", a)
	}
}

// TestResponseSigVector 锁定 X-Response-Sig 的构造。
//
// 来源：zju-connect `client/atrust/auth/request.go` 的
//
//	expected := sangforHMAC(sangforSignatureKey(data), body)
//
// 消息就是响应体原文，不含 URL。这一条曾经让我走过弯路——DLL 里能看到
// `normalizeUrl` 与 `hmac encode uri()`，但那是另一个代码路径（§29.11）。
func TestResponseSigVector(t *testing.T) {
	d := &antiMITMData{
		DevicePubKeyMod: vecPubMod,
		DevicePubKeyExp: vecPubExp,
		Challenge:       vecChal,
	}
	key := signKeyFor(d)

	// 用测试向量里的 body 验证：签名只依赖 key 与字节。
	body := []byte(`{"code":0,"data":{"nonce":"abc","antiMITMEnable":1}}`)
	got := computeResponseSig(key, body)

	if len(got) != 64 {
		t.Fatalf("签名长度 = %d，期望 64 hex", len(got))
	}
	if got != strings.ToUpper(got) {
		t.Error("签名应为大写 hex")
	}
	// 同一份输入必须稳定
	if again := computeResponseSig(key, body); again != got {
		t.Error("同一输入两次签名不一致")
	}
	// 改一个字节就必须变
	body2 := []byte(`{"code":0,"data":{"nonce":"abd","antiMITMEnable":1}}`)
	if computeResponseSig(key, body2) == got {
		t.Error("响应体变化后签名未变——说明签名没覆盖 body")
	}
}

// TestResponseSigMatchesZjuConnectRule 复刻 zju-connect 的算法做对照实现。
//
// 不 import 对方代码（AGPL），只按文档描述独立写一遍，两边必须一致。
func TestResponseSigMatchesZjuConnectRule(t *testing.T) {
	d := &antiMITMData{
		DevicePubKeyMod: vecPubMod,
		DevicePubKeyExp: vecPubExp,
		Challenge:       vecChal,
	}
	// 独立实现：first = SHA256(mod+exp+salt)，key = first XOR SHA256(upperhex(first)+chal)
	first := sha256.Sum256([]byte(vecPubMod + vecPubExp + signatureSalt))
	h := strings.ToUpper(hex.EncodeToString(first[:]))
	second := sha256.Sum256([]byte(h + vecChal))
	ref := make([]byte, 32)
	for i := range ref {
		ref[i] = first[i] ^ second[i]
	}

	if !bytes.Equal(ref, signKeyFor(d)) {
		t.Fatal("signKey 与独立实现不一致")
	}

	body := []byte("hello")
	mac := hmac.New(sha256.New, ref)
	mac.Write(body)
	want := strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
	if got := computeResponseSig(signKeyFor(d), body); got != want {
		t.Fatalf("响应签名不一致: got %s want %s", got, want)
	}
}
