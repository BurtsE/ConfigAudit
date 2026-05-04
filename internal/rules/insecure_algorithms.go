package rules

import (
	"fmt"
	"strings"
)

type InsecureAlgorithmsRule struct{}

func NewInsecureAlgorithmsRule() *InsecureAlgorithmsRule {
	return &InsecureAlgorithmsRule{}
}

func (r *InsecureAlgorithmsRule) Name() string {
	return "insecure-algorithms"
}

func (r *InsecureAlgorithmsRule) Check(cfg map[string]any) ([]Finding, error) {
	var findings []Finding

	traverse(cfg, []string{}, func(path []string, key string, value any) {
		currentPath := strings.Join(path, ".") + "." + key

		if strValue, ok := value.(string); ok {
			lowerValue := strings.ToLower(strValue)

			hashKeys := []string{
				"hash_algorithm", "hash.algorithm", "crypto.hash",
				"crypto.hash_algorithm", "digest.algorithm", "message_digest",
				"hash", "algorithm", "digest", "md", "sha",
			}

			for _, hashKey := range hashKeys {
				if strings.HasSuffix(currentPath, hashKey) || strings.Contains(currentPath, "."+hashKey) {
					if r.isInsecureHashAlgorithm(strValue) {
						findings = append(findings, Finding{
							Severity:       SeverityHigh,
							Rule:           r.Name(),
							Message:        fmt.Sprintf("Слишком слабый алгоритм хэширования - %s", strValue),
							Recommendation: "Замените его на более безопасный",
							Path:           currentPath,
						})
						break
					}
				}
			}

			encryptKeys := []string{
				"encryption_algorithm", "crypto.algorithm", "crypto.encryption",
				"cipher.algorithm", "encryption.method", "cipher_suite",
				"cipher", "encryption", "algorithm", "crypto", "tls_cipher",
			}

			for _, encryptKey := range encryptKeys {
				if strings.HasSuffix(currentPath, encryptKey) || strings.Contains(currentPath, "."+encryptKey) {
					if r.isInsecureEncryptionAlgorithm(strValue) {
						findings = append(findings, Finding{
							Severity:       SeverityHigh,
							Rule:           r.Name(),
							Message:        fmt.Sprintf("Слишком слабый алгоритм шифрования - %s", strValue),
							Recommendation: "Замените его на более безопасный",
							Path:           currentPath,
						})
						break
					}
				}
			}

			tlsKeys := []string{
				"tls_version", "tls.min_version", "ssl_version", "tls.max_version",
				"min_tls", "max_tls", "tls", "ssl", "protocol_version",
			}

			for _, tlsKey := range tlsKeys {
				if strings.HasSuffix(currentPath, tlsKey) || strings.Contains(currentPath, "."+tlsKey) {
					if strings.Contains(lowerValue, "sslv3") || strings.Contains(lowerValue, "tls1.0") || strings.Contains(lowerValue, "tls1.1") {
						findings = append(findings, Finding{
							Severity:       SeverityHigh,
							Rule:           r.Name(),
							Message:        fmt.Sprintf("Используется небезопасная версия TLS - %s", strValue),
							Recommendation: "Используйте TLS 1.2 или выше",
							Path:           currentPath,
						})
						break
					}
				}
			}
		}
	})

	return findings, nil
}

func (r *InsecureAlgorithmsRule) isInsecureHashAlgorithm(algorithm string) bool {
	lowerAlgorithm := strings.ToLower(algorithm)
	return strings.Contains(lowerAlgorithm, "md5") ||
		strings.Contains(lowerAlgorithm, "sha1") ||
		strings.Contains(lowerAlgorithm, "ripemd")
}

func (r *InsecureAlgorithmsRule) isInsecureEncryptionAlgorithm(algorithm string) bool {
	lowerAlgorithm := strings.ToLower(algorithm)
	return strings.Contains(lowerAlgorithm, "des") ||
		strings.Contains(lowerAlgorithm, "3des") ||
		strings.Contains(lowerAlgorithm, "rc4") ||
		strings.Contains(lowerAlgorithm, "blowfish") ||
		strings.Contains(lowerAlgorithm, "cast") ||
		strings.Contains(lowerAlgorithm, "idea")
}
