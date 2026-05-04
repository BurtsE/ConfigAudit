package reporter

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/BurtsE/config-audit/internal/rules"
)

// ConsoleReporter formats and prints findings to the console
type ConsoleReporter struct {
	colorEnabled bool
}

func NewConsoleReporter(colorEnabled bool) *ConsoleReporter {
	return &ConsoleReporter{
		colorEnabled: colorEnabled,
	}
}

func (r *ConsoleReporter) Print(findings []rules.Finding) {
	if len(findings) == 0 {
		fmt.Println("Уязвимостей не найдено.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	if r.colorEnabled {
		fmt.Fprintf(w, "\n%s\t%s\t%s\t%s\n", r.colorize("LEVEL", "bold"), r.colorize("Правило", "bold"), r.colorize("Описание", "bold"), r.colorize("Рекомендация", "bold"))
	} else {
		fmt.Fprintf(w, "\nLEVEL\tПравило\tОписание\tРекомендация\n")
	}

	for _, finding := range findings {
		level := string(finding.Severity)
		rule := finding.Rule
		description := finding.Message
		recommendation := finding.Recommendation

		if r.colorEnabled {
			level = r.colorizeSeverity(level, finding.Severity)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", level, rule, description, recommendation)
	}

	fmt.Println()
}

func (r *ConsoleReporter) colorizeSeverity(level string, severity rules.Severity) string {
	switch severity {
	case rules.SeverityHigh:
		return r.colorize(level, "red")
	case rules.SeverityMedium:
		return r.colorize(level, "yellow")
	case rules.SeverityLow:
		return r.colorize(level, "blue")
	default:
		return level
	}
}

func (r *ConsoleReporter) colorize(text string, color string) string {
	if !r.colorEnabled {
		return text
	}

	colors := map[string]string{
		"red":    "\033[31m",
		"yellow": "\033[33m",
		"blue":   "\033[34m",
		"bold":   "\033[1m",
		"reset":  "\033[0m",
	}

	if colorCode, exists := colors[color]; exists {
		return fmt.Sprintf("%s%s%s", colorCode, text, colors["reset"])
	}

	return text
}

func (r *ConsoleReporter) PrintSummary(findings []rules.Finding) {
	if len(findings) == 0 {
		fmt.Println("Уязвимостей не найдено.")
		return
	}

	counts := make(map[rules.Severity]int)
	for _, finding := range findings {
		counts[finding.Severity]++
	}

	fmt.Println("\nСводка:")
	fmt.Printf("  Высокая уязвимость: %d\n", counts[rules.SeverityHigh])
	fmt.Printf("  Средняя уязвимость: %d\n", counts[rules.SeverityMedium])
	fmt.Printf("  Низкая уязвимость: %d\n", counts[rules.SeverityLow])
	fmt.Printf("  Всего найдено: %d\n", len(findings))
}

func (r *ConsoleReporter) PrintJSON(findings []rules.Finding) {
	fmt.Println("[")
	for i, finding := range findings {
		fmt.Printf(`  {
		  "severity": "%s",
		  "rule": "%s",
		  "message": "%s",
		  "recommendation": "%s",
		  "path": "%s"
		}`, finding.Severity, finding.Rule, finding.Message, finding.Recommendation, finding.Path)

		if i < len(findings)-1 {
			fmt.Println(",")
		} else {
			fmt.Println()
		}
	}
	fmt.Println("]")
}
