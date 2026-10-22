package main

// antimitm.go — 反中间人应答材料的计算（§29）。
//
// 官方客户端在拿到 authConfig 后会做两道**本地**校验，mock 作为网络对端
// 无法影响判定过程，只能把正确的值算好发下去：
//
//	checkChanllege              比对 encryptedChallenge
//	checkMITMAttackReqInvalid   比对 mitmSig
//
// 这两道门的输入**全部由 mock 自己产生**（challenge、设备公钥、以及整个
// antiMITMAttackData），因此两个值都是确定性的、可以预先算出来的。
// §26.5 那套「从客户端日志回读 local 值」的权宜之计不再需要。
//
// 算法来自公开的开源实现（Mythologyli/zju-connect，AGPL-3.0），
// 此处是按算法事实独立重写的，未复制其代码。详见
// .backup/atrust/ATRUST_PROTOCOL_ANALYSIS.md §29 与
// .backup/atrust/external/README.md。

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	// challengeSalt 参与 encryptedChallenge 的密钥派生。
	challengeSalt = "OrHWuJz7gku5awmVb5w1sKTmfeCWHmzokBxmn0sn0faIcv1G10PdrbbRGKBrrZ3m"

	// signatureSalt 参与 mitmSig 的密钥派生。
	// 这就是 §27.4 里那个在 DLL 中被按 16 B 分块重排的 u8b6vopX… 串。
	signatureSalt = "3uW5IEy8KwDaOMK8uw1TmNr50U3aK1Qdu8b6vopXxGstzan3AJXxVNR6piuKi5Nq"
)

// computeEncryptedChallenge 计算下发的 encryptedChallenge。
//
//	key = SHA256(mod + exp + challengeSalt)[0:16]
//	iv  = SHA256(mod + exp + challengeSalt)[16:32]
//	out = UPPER_HEX( AES-128-CBC-PKCS7( challenge, key, iv ) )
//
// 注意明文是 challenge 的 **base64 字符串本身**，不是解码后的 128 字节。
// 这一点搞错会算出一串同样长度但完全不同的 hex，且现象上无法与「算法不对」区分。
func computeEncryptedChallenge(pubMod, pubExp, challenge string) string {
	material := sha256.Sum256([]byte(pubMod + pubExp + challengeSalt))

	block, err := aes.NewCipher(material[0:16])
	if err != nil {
		panic("aes.NewCipher: " + err.Error())
	}

	padded := pkcs7Pad([]byte(challenge), aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, material[16:32]).CryptBlocks(out, padded)
	return strings.ToUpper(hex.EncodeToString(out))
}

// computeMitmSig 计算下发的 mitmSig。
//
//	signKey = HEXDECODE(UPPER_HEX(SHA256(mod+exp+salt)))
//	          XOR SHA256( UPPER_HEX(SHA256(mod+exp+salt)) + challenge )
//	origin  = 递归收集所有标量字段（跳过 mitmSig）→ 按 key 排序 → "k:v" 用 "&" 连接
//	mitmSig = UPPER_HEX( HMAC-SHA256( signKey, origin ) )
//
// rawAntiMITM 必须是 mock **实际下发的** antiMITMAttackData 的 JSON 字节。
// 客户端是对收到的原文做同样的收集，所以 mock 在序列化前后必须保持一致。
func computeMitmSig(pubMod, pubExp, challenge string, rawAntiMITM []byte) (string, error) {
	d := &antiMITMData{DevicePubKeyMod: pubMod, DevicePubKeyExp: pubExp, Challenge: challenge}
	key := signKeyFor(d)

	origin, err := mitmOriginString(rawAntiMITM)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(origin))
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil))), nil
}

// mitmOriginString 把 antiMITMAttackData 压成参与签名的规范串。
func mitmOriginString(raw []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber() // 避免大整数变成 float64 后被格式化丢精度

	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}

	fields := map[string]string{}
	collectMitmScalars(value, fields)

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+fields[k])
	}
	return strings.Join(parts, "&"), nil
}

// collectMitmScalars 递归收集标量字段。
//
// map / array 本身不产生条目，只用于向下递归；`mitmSig` 必须跳过，
// 否则签名会自指，永远算不出稳定的值。
func collectMitmScalars(value any, fields map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		for k, child := range typed {
			if k == "mitmSig" {
				continue
			}
			switch child.(type) {
			case map[string]any, []any:
				collectMitmScalars(child, fields)
			default:
				fields[k] = mitmScalarString(child)
			}
		}
	case []any:
		for _, child := range typed {
			collectMitmScalars(child, fields)
		}
	}
}

// mitmScalarString 是标量的字符串化规则，必须与客户端逐条一致：
// bool 走 true/false、数字保留原文、null 写作 "null"。
func mitmScalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case json.Number:
		return typed.String()
	case nil:
		return "null"
	default:
		return fmt.Sprint(typed)
	}
}

func pkcs7Pad(in []byte, blockSize int) []byte {
	n := blockSize - len(in)%blockSize
	out := make([]byte, len(in)+n)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// computeResponseSig 计算响应的 X-Response-Sig。
//
// 来源：zju-connect `client/atrust/auth/request.go` 的
//
//	expected := sangforHMAC(sangforSignatureKey(data), body)
//	actual   := strings.ToUpper(resp.Header.Get("X-Response-Sig"))
//
// 也就是说：**HMAC-SHA256(signKey, 响应体原文)**。
// 消息只有响应体字节，不含 URL、不含时间戳、不含 traceId。
//
// 这一点很关键：之前从 `SdpPcMITMAdapter.dll` 里看到的 `normalizeUrl`
// 与 `hmac encode uri()` 属于**另一条**代码路径（X-Request-Sig 或证书校验），
// 把它们当成响应签名的消息构造会得出永远对不上的结果（§29.11 的弯路）。
//
// key 用的就是 mitmSig 那套 signKey：signKey 由 challenge + 设备公钥派生，
// 见 §29.2.2。签名与签名密钥是同一个，只是消息不同。
func computeResponseSig(signKey []byte, body []byte) string {
	mac := hmac.New(sha256.New, signKey)
	mac.Write(body)
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

// signKeyFor 从 antiMITMData 里派生 signKey。
//
// 与 computeMitmSig 用的派生完全一致，抽出来避免两处各写一遍。
func signKeyFor(d *antiMITMData) []byte {
	first := sha256.Sum256([]byte(d.DevicePubKeyMod + d.DevicePubKeyExp + signatureSalt))
	firstHex := strings.ToUpper(hex.EncodeToString(first[:]))

	second := sha256.Sum256([]byte(firstHex + d.Challenge))

	key := make([]byte, sha256.Size)
	for i := range key {
		key[i] = first[i] ^ second[i]
	}
	return key
}

// fillAntiMITM 给一整块 antiMITMData 补上两个可验证的值。
//
// 若调用方已显式设置 EncryptedChallenge（-challenge-answer 覆盖），
// 则保留它、只补算 mitmSig——但那样 mitmSig 覆盖的就不是一个「正确的」
// encryptedChallenge，客户端的第一道门会先失败。这是有意的：该开关只用于
// 对照实验，正常路径下 EncryptedChallenge 留空由这里计算。
//
// 做法：先把 mitmSig 留空序列化一次 → 用这份 JSON 算签名 → 再填回去。
// 因为 origin 收集时会跳过 mitmSig，所以「留空算」与「填好算」结果相同；
// 用同一份序列化结果可以保证 mock 下发的字节与签名覆盖的字节完全一致。
func fillAntiMITM(d *antiMITMData) error {
	if d.DevicePubKeyMod == "" || d.DevicePubKeyExp == "" || d.Challenge == "" {
		return fmt.Errorf("antiMITM 材料不完整：pubMod/pubExp/challenge 都不能为空")
	}

	if d.EncryptedChallenge == "" {
		d.EncryptedChallenge = computeEncryptedChallenge(d.DevicePubKeyMod, d.DevicePubKeyExp, d.Challenge)
	}

	d.MitmSig = ""
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}

	sig, err := computeMitmSig(d.DevicePubKeyMod, d.DevicePubKeyExp, d.Challenge, raw)
	if err != nil {
		return err
	}
	d.MitmSig = sig
	return nil
}
