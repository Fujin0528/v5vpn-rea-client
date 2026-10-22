package main

// keys.go — 生成并持久化 mock 网关的 RSA 密钥对与自签 TLS 证书。
//
// 设计要点：
//   - 官方客户端不校验网关 TLS 证书（aTrustTray/main.js 里有
//     `App.commandLine.appendSwitch("ignore-certificate-errors")`，
//     原生侧也有 "ignore cert check fail" 分支），所以自签证书足够。
//   - RSA 私钥必须持久化：每次重启换新公钥会让客户端缓存的 authConfig
//     失效，导致难以排查的"密文解不开"现象。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	rsaKeyFile  = "mock_rsa.pem"
	tlsCertFile = "mock_tls_cert.pem"
	tlsKeyFile  = "mock_tls_key.pem"
)

// loadOrCreateRSA 读取或生成 2048 位 RSA 密钥（网关下发给客户端的 pubKey）。
func loadOrCreateRSA(dir string) (*rsa.PrivateKey, bool, error) {
	path := filepath.Join(dir, rsaKeyFile)
	raw, err := os.ReadFile(path)
	if err == nil {
		blk, _ := pem.Decode(raw)
		if blk == nil {
			return nil, false, fmt.Errorf("%s: 不是合法 PEM", path)
		}
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, false, fmt.Errorf("%s: 解析私钥失败: %w", path, err)
		}
		return k, true, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, false, fmt.Errorf("生成 RSA 密钥失败: %w", err)
	}
	blk := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, false, err
	}
	return k, false, nil
}

// loadOrCreateTLSCert 生成自签证书（含 127.0.0.1 / localhost，方便客户端直连）。
func loadOrCreateTLSCert(dir string) (certPath, keyPath string, created bool, err error) {
	certPath = filepath.Join(dir, tlsCertFile)
	keyPath = filepath.Join(dir, tlsKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath, false, nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", false, fmt.Errorf("生成 TLS 私钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", false, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"aTrust Mock Gateway"},
			CommonName:   "sdp.mock.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames: []string{
			"localhost", "sdp.mock.local", "sdp.ssl.com", // sdp.ssl.com 用于对齐真实网关证书 CN
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", false, fmt.Errorf("签发自签证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", false, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", false, err
	}
	return certPath, keyPath, true, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// pubKeyHex 返回 RSA 模数的 UPPER-HEX 表示——与真实网关 authConfig.pubKey
// 的格式一致（512 hex 字符 = 2048 bit，无 0x 前缀、无前导零填充）。
func pubKeyHex(k *rsa.PrivateKey) string {
	return fmt.Sprintf("%X", k.N)
}
