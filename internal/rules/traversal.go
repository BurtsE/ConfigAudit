package rules

import (
	"fmt"
	"strings"
)

func traverse(cfg map[string]any, path []string, visitor func(path []string, key string, value any)) {
	for key, value := range cfg {
		currentPath := append(path, key)
		visitor(currentPath, key, value)

		if nestedMap, ok := value.(map[string]any); ok {
			traverse(nestedMap, currentPath, visitor)
		}
		if slice, ok := value.([]any); ok {
			for i, item := range slice {
				if nestedMap, ok := item.(map[string]any); ok {
					itemPath := append(currentPath, fmt.Sprintf("[%d]", i))
					traverse(nestedMap, itemPath, visitor)
				}
			}
		}
	}
}


func isSecretValue(value string) bool {
	prefixes := []string{
		"${", "vault:", "enc:", "secret:", "token:", "api_key:",
		"-----BEGIN", "-----BEGIN ", "-----BEGIN PRIVATE KEY",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	if isHash(value) {
		return true
	}

	return false
}

func isHash(value string) bool {
	if len(value) == 32 || len(value) == 40 || len(value) == 64 {
		for _, c := range value {
			if !((c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'f') ||
				(c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}

	return false
}
