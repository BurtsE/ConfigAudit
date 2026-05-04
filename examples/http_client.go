package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Использование: http_client <файл-конфигурации> [адрес-сервера]")
		os.Exit(1)
	}

	configFile := os.Args[1]
	serverURL := "http://localhost:8080"
	if len(os.Args) > 2 {
		serverURL = os.Args[2]
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Ошибка чтения файла конфигурации: %v\n", err)
		os.Exit(1)
	}

	requestBody := bytes.NewReader(data)
	req, err := http.NewRequest("POST", serverURL+"/config/check", requestBody)
	if err != nil {
		fmt.Printf("Ошибка создания запроса: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Ошибка отправки запроса: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Ошибка чтения ответа: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Статус ответа: %s\n", resp.Status)
	fmt.Printf("Тело ответа:\n%s\n", string(body))

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal(body, &jsonResponse); err == nil {
		prettyJSON, _ := json.MarshalIndent(jsonResponse, "", "  ")
		fmt.Printf("Форматированный JSON ответ:\n%s\n", string(prettyJSON))
	}
}
