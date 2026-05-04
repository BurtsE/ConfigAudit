package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/BurtsE/config-audit/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Использование: grpc_client <файл-конфигурации> [адрес-сервера]")
		os.Exit(1)
	}

	configFile := os.Args[1]
	serverAddress := "localhost:9090"
	if len(os.Args) > 2 {
		serverAddress = os.Args[2]
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Ошибка чтения файла конфигурации: %v", err)
	}

	conn, err := grpc.NewClient(serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Не удалось подключиться к серверу: %v", err)
	}
	defer conn.Close()
	client := pb.NewConfigAuditServiceClient(conn)

	req := &pb.AuditConfigRequest{
		ConfigData:   data,
		ConfigFormat: "",
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*100)
	defer cancel()

	resp, err := client.AuditConfig(ctx, req)
	if err != nil {
		log.Fatalf("Ошибка аудита конфигурации: %v", err)
	}

	fmt.Printf("Результаты аудита:\n")
	fmt.Printf("Всего найдено проблем: %d\n", resp.Summary.Total)
	fmt.Printf("Высокая критичность: %d\n", resp.Summary.High)
	fmt.Printf("Средняя критичность: %d\n", resp.Summary.Medium)
	fmt.Printf("Низкая критичность: %d\n", resp.Summary.Low)
	fmt.Println()

	fmt.Println("Подробные результаты:")
	for i, finding := range resp.Findings {
		fmt.Printf("%d. [%s] %s\n", i+1, finding.Severity, finding.Rule)
		fmt.Printf("   Сообщение: %s\n", finding.Message)
		fmt.Printf("   Рекомендация: %s\n", finding.Recommendation)
		if finding.Path != "" {
			fmt.Printf("   Путь: %s\n", finding.Path)
		}
		fmt.Println()
	}

	infoReq := &pb.GetServerInfoRequest{}
	infoResp, err := client.GetServerInfo(ctx, infoReq)
	if err != nil {
		log.Printf("Не удалось получить информацию о сервере: %v", err)
	} else {
		fmt.Printf("Информация о сервере:\n")
		fmt.Printf("  Версия: %s\n", infoResp.Version)
		fmt.Printf("  Сервис: %s\n", infoResp.ServiceName)
	}
}
