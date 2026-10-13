package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"errors"
	"strings"
)

var (
	// SettingDESKey is the hardcoded DES key in SecController.dll: "A3S7g6t5"
	SettingDESKey = []byte("A3S7g6t5")
	SettingDESIV  = []byte("A3S7g6t5")

	// AuthAESKey is the hardcoded AES-128 key in SecController.dll for login: "1234567890abcdef"
	AuthAESKey = []byte("1234567890abcdef")
	// AuthAESIV is the hardcoded AES-128 IV in SecController.dll for login: "abcdef1234567890"
	AuthAESIV = []byte("abcdef1234567890")
)

// PKCS7Pad adds PKCS7/PKCS5 padding
func PKCS7Pad(src []byte, blockSize int) []byte {
	padding := blockSize - (len(src) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS7Unpad removes PKCS7/PKCS5 padding
func PKCS7Unpad(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid ciphertext block size")
	}
	unpadding := int(src[length-1])
	if unpadding == 0 || unpadding > blockSize {
		return nil, errors.New("invalid padding value")
	}
	for i := length - unpadding; i < length; i++ {
		if src[i] != byte(unpadding) {
			return nil, errors.New("inconsistent padding bytes")
		}
	}
	return src[:length-unpadding], nil
}

// DecryptSettingPassword decrypts the password string stored in setting.xml using DES-CBC
func DecryptSettingPassword(b64Cipher string) (string, error) {
	b64Cipher = strings.TrimSpace(b64Cipher)
	if b64Cipher == "" {
		return "", nil
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(b64Cipher)
	if err != nil {
		return "", err
	}

	block, err := des.NewCipher(SettingDESKey)
	if err != nil {
		return "", err
	}

	if len(cipherBytes)%block.BlockSize() != 0 {
		return "", errors.New("ciphertext length is not a multiple of DES block size")
	}

	mode := cipher.NewCBCDecrypter(block, SettingDESIV)
	plain := make([]byte, len(cipherBytes))
	mode.CryptBlocks(plain, cipherBytes)

	unpadded, err := PKCS7Unpad(plain, block.BlockSize())
	if err != nil {
		// If unpad fails, return raw string trimmed of nulls
		return string(bytes.TrimRight(plain, "\x00")), nil
	}
	return string(unpadded), nil
}

// EncryptSettingPassword encrypts a plaintext password for saving into setting.xml
func EncryptSettingPassword(plainText string) (string, error) {
	if plainText == "" {
		return "", nil
	}
	block, err := des.NewCipher(SettingDESKey)
	if err != nil {
		return "", err
	}

	padded := PKCS7Pad([]byte(plainText), block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, SettingDESIV)
	cipherBytes := make([]byte, len(padded))
	mode.CryptBlocks(cipherBytes, padded)

	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// DecodeSettingUsername decodes base64 username from setting.xml
func DecodeSettingUsername(b64Name string) string {
	b64Name = strings.TrimSpace(b64Name)
	if b64Name == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(b64Name)
	if err != nil {
		return b64Name
	}
	return strings.TrimRight(string(raw), "\r\n\x00 ")
}

// EncodeSettingUsername encodes username into base64 for setting.xml
func EncodeSettingUsername(name string) string {
	return base64.StdEncoding.EncodeToString([]byte(name))
}

// EncryptAuthParam encrypts username or password for /vpn/user/auth/password via AES-128-CBC
func EncryptAuthParam(plainText string) (string, error) {
	if plainText == "" {
		return "", nil
	}
	block, err := aes.NewCipher(AuthAESKey)
	if err != nil {
		return "", err
	}

	padded := PKCS7Pad([]byte(plainText), block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, AuthAESIV)
	cipherBytes := make([]byte, len(padded))
	mode.CryptBlocks(cipherBytes, padded)

	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// DecryptAuthParam decrypts AES-128-CBC encrypted auth param
func DecryptAuthParam(b64Cipher string) (string, error) {
	b64Cipher = strings.TrimSpace(b64Cipher)
	if b64Cipher == "" {
		return "", nil
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(b64Cipher)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(AuthAESKey)
	if err != nil {
		return "", err
	}

	if len(cipherBytes)%block.BlockSize() != 0 {
		return "", errors.New("ciphertext length is not a multiple of AES block size")
	}

	mode := cipher.NewCBCDecrypter(block, AuthAESIV)
	plain := make([]byte, len(cipherBytes))
	mode.CryptBlocks(plain, cipherBytes)

	unpadded, err := PKCS7Unpad(plain, block.BlockSize())
	if err != nil {
		return string(bytes.TrimRight(plain, "\x00")), nil
	}
	return string(unpadded), nil
}
