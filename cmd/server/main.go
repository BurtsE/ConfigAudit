package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/BurtsE/config-audit/internal/rules"
	grpcsrv "github.com/BurtsE/config-audit/internal/servers/grpc"
	httpsrv "github.com/BurtsE/config-audit/internal/servers/httpserver"
)

type Config struct {
	httpPort int
	grpcPort int
	silent   bool
}

func main() {
	config := parseFlags()

	registry := rules.NewRuleRegistry()
	registry.Register(rules.NewDebugLoggingRule())
	registry.Register(rules.NewSecretsRule())
	registry.Register(rules.NewServerBindingRule())
	registry.Register(rules.NewTLSVerificationRule())
	registry.Register(rules.NewInsecureAlgorithmsRule())

	httpServer := httpsrv.NewHttpServer(config.httpPort, registry)
	grpcServer := grpcsrv.CreateServer(registry)

	errChan := make(chan error, 2)

	if config.httpPort > 0 {
		go func() {
			log.Printf("Запуск HTTP-сервера на порту %d", config.httpPort)
			if err := httpServer.Start(); err != nil {
				errChan <- fmt.Errorf("Ошибка HTTP-сервера: %v", err)
			}
		}()
	}

	if config.grpcPort > 0 {
		go func() {
			log.Printf("Запуск gRPC-сервера на порту %d", config.grpcPort)
			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.grpcPort))
			if err != nil {
				errChan <- fmt.Errorf("Не удалось создать слушатель gRPC: %v", err)
				return
			}
			if err := grpcsrv.StartServer(grpcServer, listener); err != nil {
				errChan <- fmt.Errorf("Ошибка gRPC-сервера: %v", err)
			}
		}()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		log.Fatalf("Ошибка сервера: %v", err)
	case sig := <-sigChan:
		log.Printf("Получен сигнал %v, завершение работы серверов...", sig)

		if config.httpPort > 0 {
			if err := httpServer.Stop(); err != nil {
				log.Printf("Ошибка при остановке HTTP-сервера: %v", err)
			}
		}

		if config.grpcPort > 0 {
			grpcServer.GracefulStop()
		}
		log.Println("Серверы остановлены корректно")
	}
}

func parseFlags() Config {
	config := Config{}

	flag.IntVar(&config.httpPort, "http-port", 8080, "Порт HTTP-сервера (0 для отключения)")
	flag.IntVar(&config.grpcPort, "grpc-port", 9090, "Порт gRPC-сервера (0 для отключения)")
	flag.BoolVar(&config.silent, "silent", false, "Тихий режим (без логирования)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Использование: %s [опции]\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Сервер аудита конфигурации, предоставляющий конечные точки HTTP и gRPC\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nПримеры:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --http-port 8080 --grpc-port 9090    # Запустить оба сервера\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --http-port 8080                     # Запустить только HTTP-сервер\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --grpc-port 9090                     # Запустить только gRPC-сервер\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --http-port 0 --grpc-port 0          # Отключить оба сервера\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --silent                             # Тихий режим (без логирования)\n", os.Args[0])
	}

	flag.Parse()

	return config
}
