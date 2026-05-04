package rules

import (
	"strings"
)

type TLSVerificationRule struct{}

func NewTLSVerificationRule() *TLSVerificationRule {
	return &TLSVerificationRule{}
}

func (r *TLSVerificationRule) Name() string {
	return "tls-verification"
}

func (r *TLSVerificationRule) Check(cfg map[string]any) ([]Finding, error) {
	var findings []Finding

	traverse(cfg, []string{}, func(path []string, key string, value any) {
		currentPath := strings.Join(path, ".") + "." + key

		if boolValue, ok := value.(bool); ok {
			if boolValue {
				insecureKeys := []string{
					"insecure_skip_verify", "skip_verify", "verify_ssl",
					"verify_ssl_certificate", "skip_cert_verify", "skip_certificate_verify",
					"allow_insecure", "disable_verify", "no_verify",
				}

				for _, insecureKey := range insecureKeys {
					if strings.HasSuffix(currentPath, insecureKey) || strings.Contains(currentPath, "."+insecureKey) {
						findings = append(findings, Finding{
							Severity:       SeverityHigh,
							Rule:           r.Name(),
							Message:        "Проверка TLS/SSL отключена.",
							Recommendation: "Включите проверку сертификатов. Для тестирования используйте такие инструменты, как mkcert, для проверки локальных сертификатов.",
							Path:           currentPath,
						})
						break
					}
				}
			}
		}

		if strValue, ok := value.(string); ok {
			lowerValue := strings.ToLower(strValue)
			if lowerValue == "none" || lowerValue == "insecure" || lowerValue == "disabled" {
				verifyKeys := []string{
					"verify_mode", "security_mode", "ssl_mode", "tls_mode",
					"verification", "ssl_verify", "tls_verify",
				}

				for _, verifyKey := range verifyKeys {
					if strings.HasSuffix(currentPath, verifyKey) || strings.Contains(currentPath, "."+verifyKey) {
						findings = append(findings, Finding{
							Severity:       SeverityHigh,
							Rule:           r.Name(),
							Message:        "Проверка TLS/SSL отключена.",
							Recommendation: "Включите проверку сертификатов. Для тестирования используйте такие инструменты, как mkcert, для проверки локальных сертификатов.",
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
