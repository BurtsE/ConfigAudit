package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/BurtsE/config-audit/internal/parser"
	"github.com/BurtsE/config-audit/internal/reporter"
	"github.com/BurtsE/config-audit/internal/rules"
)

type Config struct {
	configPath string
	silent     bool
	stdin      bool
}

func main() {
	config := parseFlags()

	var data []byte
	var err error

	if config.stdin {
		data, err = readFromStdin()
	} else {
		if config.configPath == "" {
			fmt.Fprintf(os.Stderr, "Ошибка: Если не используется параметр --stdin, необходимо указать путь к файлу конфигурации\n")
			os.Exit(2)
		}

		if err := validateFilePath(config.configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			os.Exit(2)
		}

		data, err = readFileContent(config.configPath)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
		os.Exit(2)
	}

	format, err := parser.DetectFormat(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
		os.Exit(2)
	}

	cfg, err := parser.ParseConfig(data, format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
		os.Exit(2)
	}

	registry := rules.NewRuleRegistry()
	registry.Register(rules.NewDebugLoggingRule())
	registry.Register(rules.NewSecretsRule())
	registry.Register(rules.NewServerBindingRule())
	registry.Register(rules.NewTLSVerificationRule())
	registry.Register(rules.NewInsecureAlgorithmsRule())

	findings, err := registry.Run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
		os.Exit(2)
	}

	reporter := reporter.NewConsoleReporter(true)
	reporter.Print(findings)

	reporter.PrintSummary(findings)

	if len(findings) > 0 && !config.silent {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.configPath, "config", "", "Путь к файлу конфигурации")
	flag.StringVar(&config.configPath, "f", "", "Path to configuration file (shorthand)")
	flag.BoolVar(&config.silent, "silent", false, "Не завершать работу при обнаружении проблем")
	flag.BoolVar(&config.silent, "s", false, "Не завершайть работу при обнаружении проблем")
	flag.BoolVar(&config.stdin, "stdin", false, "Чтение конфигурации из стандартного ввода")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Применение: %s [флаг] [путь к файлу]\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Утилита для анализа конфигурационных файлов web-приложений\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nПримеры:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  %s config.json                    # Аудит config.json\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --stdin < config.yaml          # Чтение из стандартного потока ввода\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  %s -s config.json                 # Silent mode\n", os.Args[0])
	}

	flag.Parse()

	if flag.NArg() == 1 {
		config.configPath = flag.Arg(0)
		config.stdin = false
	} else if flag.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "Ошибка: слишком много аргументов\n")
		flag.Usage()
		os.Exit(2)
	}

	return config
}

func readFromStdin() ([]byte, error) {
	if isTerminal() {
		return nil, fmt.Errorf("Стандартный поток ввода не перенаправляется")
	}

	return io.ReadAll(os.Stdin)
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func validateFilePath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("файл не существует: %s", path)
		}
		return fmt.Errorf("Отсутствует доступ к файлу: %v", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("Путь не является обычным файлом: %s", path)
	}

	maxSize := int64(10 * 1024 * 1024) // 10MB
	if info.Size() > maxSize {
		return fmt.Errorf("Размер файла превышает лимит в %d байт", maxSize)
	}

	return nil
}

func readFileContent(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл: %v", err)
	}
	return data, nil
}
