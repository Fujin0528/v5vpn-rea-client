package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	outPath := flag.String("out", "results/test-client.p12", "Output path for the .p12 certificate file")
	cn := flag.String("cn", "Leadsec-Admin-Cert", "Common Name (CN) for the client certificate")
	pwd := flag.String("pwd", "123456", "Password protecting the PKCS#12 bundle")
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create dir: %v\n", err)
		os.Exit(1)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate RSA key: %v\n", err)
		os.Exit(1)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   *cn,
			Organization: []string{"网御星云安全接入测试中心"},
			Country:      []string{"CN"},
		},
		NotBefore:   time.Now().Add(-2 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse certificate: %v\n", err)
		os.Exit(1)
	}

	encoded, err := pkcs12.Modern.Encode(key, cert, nil, *pwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode pkcs12: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outPath, encoded, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write file: %v\n", err)
		os.Exit(1)
	}

	absPath, _ := filepath.Abs(*outPath)
	fmt.Printf("[OK] Certificate successfully generated: %s (Password: %s)\n", absPath, *pwd)
}
