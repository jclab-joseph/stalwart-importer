package mailbox

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
)

func decodeUtf7Block(block string) (string, error) {
	// "&-" → 그냥 "&"
	if block == "&-" {
		return "&", nil
	}

	// 앞뒤 & 와 - 제거
	section := block[1 : len(block)-1]

	// Modified Base64: ',' -> '/'
	section = strings.ReplaceAll(section, ",", "/")

	// Base64 decode
	decoded, err := base64.StdEncoding.DecodeString(section + strings.Repeat("=", (4-len(section)%4)%4))
	if err != nil {
		return "", fmt.Errorf("base64 decode error: %v", err)
	}

	// UTF-16BE -> UTF-8
	if len(decoded)%2 != 0 {
		return "", fmt.Errorf("invalid utf-16 bytes length")
	}
	ucs2 := make([]uint16, len(decoded)/2)
	for i := 0; i < len(ucs2); i++ {
		ucs2[i] = uint16(decoded[2*i])<<8 | uint16(decoded[2*i+1])
	}
	runes := utf16.Decode(ucs2)
	return string(runes), nil
}

func DecodeIMAPUTF7(input string) (string, error) {
	re := regexp.MustCompile(`&[^-]*-`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		decoded, err := decodeUtf7Block(match)
		if err != nil {
			return match
		}
		return decoded
	}), nil
}
