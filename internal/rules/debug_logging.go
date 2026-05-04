package rules

import (
	"strings"
)

type DebugLoggingRule struct{}

func NewDebugLoggingRule() *DebugLoggingRule {
	return &DebugLoggingRule{}
}

func (r *DebugLoggingRule) Name() string {
	return "debug-logging"
}

func (r *DebugLoggingRule) Check(cfg map[string]any) ([]Finding, error) {
	var findings []Finding

	traverse(cfg, []string{}, func(path []string, key string, value any) {
		currentPath := strings.Join(path, ".") + "." + key

		if strValue, ok := value.(string); ok {
			if strings.EqualFold(strValue, "debug") {
				debugPaths := []string{
					"level", "log_level", "logging_level",
					"debug_level", "verbosity",
				}

				for _, debugPath := range debugPaths {
					if strings.HasSuffix(currentPath, debugPath) || strings.Contains(currentPath, "."+debugPath) {
						findings = append(findings, Finding{
							Severity:       SeverityLow,
							Rule:           r.Name(),
							Message:        "Логирование в debug-режиме",
							Recommendation: "Поменяйте режим на более избирательный (info+)",
							Path:           currentPath,
						})
						break
					}
				}
			}
		}

		if boolValue, ok := value.(bool); ok {
			if boolValue {
				// Check if this is a known debug flag
				if key == "debug" || strings.HasSuffix(key, "_debug") || strings.HasSuffix(key, ".debug") {
					findings = append(findings, Finding{
						Severity:       SeverityLow,
						Rule:           r.Name(),
						Message:        "логирование в debug-режиме",
						Recommendation: "Поменяйте режим на более избирательный (info+)",
						Path:           currentPath,
					})
				}
			}
		}
	})

	return findings, nil
}
