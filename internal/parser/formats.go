package parser

import (
	"errors"
	"strings"
)

const (
	FormatJSON = "json"
	FormatYAML = "yaml"
)

var (
	ErrUnknownFormat = errors.New("неизвестный формат файла")
)

func DetectFormat(data []byte) (string, error) {
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		
		if b == '{' {
			return FormatJSON, nil
		}
		
		if b == '-' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			return FormatYAML, nil
		}
		
		return "", ErrUnknownFormat
	}
	
	return "", ErrUnknownFormat
}

func IsValidFormat(format string) bool {
	return strings.EqualFold(format, FormatJSON) || strings.EqualFold(format, FormatYAML)
}