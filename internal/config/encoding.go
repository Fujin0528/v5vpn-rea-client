package config

import (
	"bytes"
	"io"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// EnsureUTF8 converts raw data to a UTF-8 byte slice.
// If data is already valid UTF-8, it is returned as-is.
// If it contains legacy GBK/GB2312/GB18030 characters, it is automatically decoded to UTF-8.
func EnsureUTF8(data []byte) []byte {
	// Strip UTF-8 BOM if present
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	if utf8.Valid(data) {
		return data
	}

	// Fallback decode from GBK
	reader := transform.NewReader(bytes.NewReader(data), simplifiedchinese.GBK.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err == nil && utf8.Valid(decoded) {
		return decoded
	}

	// Second fallback: GB18030
	reader18030 := transform.NewReader(bytes.NewReader(data), simplifiedchinese.GB18030.NewDecoder())
	decoded18030, err := io.ReadAll(reader18030)
	if err == nil && utf8.Valid(decoded18030) {
		return decoded18030
	}

	return data
}
