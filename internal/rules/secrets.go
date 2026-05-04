package rules

import (
	"strings"
)

type SecretsRule struct{}

func NewSecretsRule() *SecretsRule {
	return &SecretsRule{}
}

func (r *SecretsRule) Name() string {
	return "secrets"
}

func (r *SecretsRule) Check(cfg map[string]any) ([]Finding, error) {
	var findings []Finding

	secretKeyPatterns := []string{
		"password",
		"secret",
		"token",
		"key",
		"api_key",
		"apikey",
		"auth_token",
		"access_token",
		"refresh_token",
		"private_key",
		"public_key",
		"certificate",
		"ssl_key",
		"db_password",
		"database_password",
		"jwt_secret",
		"jwt_key",
		"oauth_secret",
		"oauth_key",
		"slack_token",
		"github_token",
		"gitlab_token",
		"aws_access_key",
		"aws_secret_key",
		"gcp_service_account_key",
		"azure_client_secret",
	}

	traverse(cfg, []string{}, func(path []string, key string, value any) {
		for _, pattern := range secretKeyPatterns {
			if strings.Contains(strings.ToLower(key), pattern) {
				if strValue, ok := value.(string); ok {
					if !isSecretValue(strValue) {
						findings = append(findings, Finding{
							Severity:       SeverityHigh,
							Rule:           r.Name(),
							Message:        "Потенциальный секрет обнаружен в конфигурации.",
							Recommendation: "Используйте переменные среды, системы управления секретами или зашифрованные значения",
							Path:           strings.Join(path, ".") + "." + key,
						})
					}
				}
			}
		}
	})

	return findings, nil
}
