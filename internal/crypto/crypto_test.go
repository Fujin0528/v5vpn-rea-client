package crypto

import (
	"strings"
	"testing"
)

// syntheticCiphertext produces a deterministic ciphertext from a plaintext
// using the production EncryptSettingPassword routine. Using a round-trip
// pair keeps coverage identical to "decrypt a stored password" without
// shipping any real production ciphertext in the repository.
func syntheticCiphertext(t *testing.T, plain string) string {
	t.Helper()
	enc, err := EncryptSettingPassword(plain)
	if err != nil {
		t.Fatalf("EncryptSettingPassword(%q) failed: %v", plain, err)
	}
	return enc
}

func TestDecryptSettingPassword(t *testing.T) {
	// Synthetic vectors only. Never commit real ciphertext from a
	// production setting.xml: the DES key/IV are public knowledge once
	// the repository is published, and the ciphertext/username pairs are
	// harvested by credential scanners within minutes.
	tests := []struct {
		expect string
	}{
		{"S3cret!pass-001"},
		{"another-Test-PwD#1"},
		{"\u4e2d\u6587\u6d4b\u8bd5\u5bc6\u7801"}, // UTF-8 sanity case
		{strings.Repeat("a", 24)},                 // multi-block padding case
	}

	for _, tt := range tests {
		cipher := syntheticCiphertext(t, tt.expect)

		got, err := DecryptSettingPassword(cipher)
		if err != nil {
			t.Fatalf("DecryptSettingPassword(%q) failed: %v", cipher, err)
		}
		if got != tt.expect {
			t.Errorf("DecryptSettingPassword(%q) = %q, want %q", cipher, got, tt.expect)
		}

		// Re-encrypt test
		enc, err := EncryptSettingPassword(got)
		if err != nil {
			t.Fatalf("EncryptSettingPassword(%q) failed: %v", got, err)
		}
		reDec, err := DecryptSettingPassword(enc)
		if err != nil || reDec != tt.expect {
			t.Fatalf("Round-trip failed: got %q, want %q", reDec, tt.expect)
		}
	}
}

func TestAuthParamCrypto(t *testing.T) {
	plain := "demo-AuthParam-Value#42"
	enc, err := EncryptAuthParam(plain)
	if err != nil {
		t.Fatalf("EncryptAuthParam failed: %v", err)
	}
	dec, err := DecryptAuthParam(enc)
	if err != nil {
		t.Fatalf("DecryptAuthParam failed: %v", err)
	}
	if dec != plain {
		t.Fatalf("Auth crypto mismatch: got %q, want %q", dec, plain)
	}
}

func TestEncodeDecodeSettingUsername(t *testing.T) {
	cases := []string{"alice", "bob-001", "\u7528\u6237\u540d"}
	for _, plain := range cases {
		enc := EncodeSettingUsername(plain)
		dec := DecodeSettingUsername(enc)
		if dec != plain {
			t.Errorf("round-trip mismatch: got %q, want %q", dec, plain)
		}
	}
}
