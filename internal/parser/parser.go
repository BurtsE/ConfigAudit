package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	ErrParseConfig = errors.New("failed to parse config")
)

func ParseConfig(data []byte, format string) (map[string]any, error) {
	if !IsValidFormat(format) {
		return nil, fmt.Errorf("%w: неверный формат: %s", ErrParseConfig, format)
	}

	var result map[string]any

	switch strings.ToLower(format) {
	case FormatJSON:
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("%w: Ошибка анализа JSON: %v", ErrParseConfig, err)
		}
	case FormatYAML:
		if err := yaml.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("%w: Ошибка  анализа YAML: %v", ErrParseConfig, err)
		}
	default:
		return nil, fmt.Errorf("%w: неподдерживаемый формат: %s", ErrParseConfig, format)
	}

	return result, nil
}