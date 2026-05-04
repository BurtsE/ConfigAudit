package rules

import (
	"strings"
)

type ServerBindingRule struct{}

func NewServerBindingRule() *ServerBindingRule {
	return &ServerBindingRule{}
}

func (r *ServerBindingRule) Name() string {
	return "server-binding"
}

func (r *ServerBindingRule) Check(cfg map[string]any) ([]Finding, error) {
	var findings []Finding

	traverse(cfg, []string{}, func(path []string, key string, value any) {
		currentPath := strings.Join(path, ".") + "." + key

		if strValue, ok := value.(string); ok {
			if strings.EqualFold(strValue, "0.0.0.0") || strings.EqualFold(strValue, "::") {
				hostKeys := []string{
					"host", "address", "bind", "listen", "endpoint",
					"hostname", "server_host", "server_address",
				}

				for _, hostKey := range hostKeys {
					if strings.HasSuffix(currentPath, hostKey) || strings.Contains(currentPath, "."+hostKey) {
						var message, recommendation string
						if strings.EqualFold(strValue, "0.0.0.0") {
							message = "Сервер привязан ко всем интерфейсам (0.0.0.0)."
							recommendation = "Используйте 127.0.0.1 или ограничьте доступ определенными IP-адресами."
						} else {
							message = "Сервер привязан ко всем интерфейсам IPv6 (::)"
							recommendation = "Используйте ::1 для локального доступа по IPv6 или ограничьте доступ определенными IP-адресами."
						}

						findings = append(findings, Finding{
							Severity:       SeverityMedium,
							Rule:           r.Name(),
							Message:        message,
							Recommendation: recommendation,
							Path:           currentPath,
						})
						break
					}
				}
			}
		}

		if strValue, ok := value.(string); ok {
			if strings.Contains(strValue, ":") {
				parts := strings.Split(strValue, ":")
				if len(parts) >= 2 {
					host := parts[0]
					if strings.EqualFold(host, "0.0.0.0") {
						portKeys := []string{
							"port", "listen_port", "server_port", "bind_port",
							"endpoint", "url", "address",
						}

						for _, portKey := range portKeys {
							if strings.HasSuffix(currentPath, portKey) || strings.Contains(currentPath, "."+portKey) {
								findings = append(findings, Finding{
									Severity:       SeverityMedium,
									Rule:           r.Name(),
									Message:        "Сервер привязан ко всем интерфейсам на порту " + parts[1],
									Recommendation: "Используйте 127.0.0.1 или ограничьте доступ определенными IP-адресами.",
									Path:           currentPath,
								})
								break
							}
						}
					}
				}
			}
		}
	})

	return findings, nil
}
