# Сервер аудита конфигураций

Сервер аудита конфигураций, предоставляющий HTTP и gRPC эндпоинты для анализа файлов конфигурации на предмет проблем безопасности.

## Возможности

- **HTTP-сервер**: RESTful API для аудита конфигураций
- **gRPC-сервер**: Высокопроизводительный RPC-сервис для аудита конфигураций
- **Поддержка форматов**: Работа с файлами конфигурации в форматах JSON и YAML
- **Правила безопасности**: Комплексный движок правил безопасности
- **Детальная отчётность**: Возвращает находки с уровнями критичности и рекомендациями

## Быстрый старт

### Запуск консольной утилиты

```
go run cmd/config-audit
```

Предусмотрены следующие параметры (флаги):
- `-s`, `--silent` - не выходить с ошибкой при наличии проблем
- `--stdin` - прочитать конфигурацию из стандартного потока ввода вместо файла

### Запуск сервера

```bash
# Запуск обоих серверов: HTTP и gRPC
go run cmd/server/main.go --http-port 8080 --grpc-port 9090

# Запуск только HTTP-сервера
go run cmd/server/main.go --http-port 8080 --grpc-port 0

# Запуск только gRPC-сервера
go run cmd/server/main.go --http-port 0 --grpc-port 9090

# Тихий режим
go run cmd/server/main.go --silent
```

### Использование HTTP-сервера

#### Эндпоинт
- `POST /config/check` — Аудит файла конфигурации

#### Запрос
```bash
curl -X POST http://localhost:8080/config/check \
  -H "Content-Type: application/octet-stream" \
  --data-binary @config.json
```

#### Ответ
```json
{
  "findings": [
    {
      "message": "Логирование в debug-режиме",
      "path": "deep.nested.config.logging.level.level",
      "recommendation": "Поменяйте режим на более избирательный (info+)",
      "rule": "debug-logging",
      "severity": "LOW"
    }
  ],
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

### Использование gRPC-сервера

#### Пример клиента
```bash
go run examples/grpc_client.go testdata/secure.json localhost:9090
```

#### Методы gRPC
- `AuditConfig` — Аудит файла конфигурации
- `GetServerInfo` — Получение информации о сервере

## Правила безопасности

Сервер включает следующие правила безопасности:

1. **Правило отладочного логирования** — Обнаруживает включённое отладочное логирование в продакшене
2. **Правило секретов** — Обнаруживает жёстко закодированные секреты и API-ключи
3. **Правило привязки сервера** — Проверяет небезопасные настройки привязки сервера
4. **Правило проверки TLS** — Валидирует конфигурации TLS/SSL
5. **Правило небезопасных алгоритмов** — Обнаруживает слабые криптографические алгоритмы

## Примеры конфигураций

### Безопасная конфигурация (JSON)
```json
{
  "logging": {
    "level": "info"
  },
  "database": {
    "ssl": true,
    "ssl_mode": "verify-full"
  }
}
```

### Небезопасная конфигурация (YAML)
```yaml
logging:
  level: debug
database:
  ssl: false
  password: "hardcoded_password"
```

## Сборка

```bash
# Генерация protobuf-файлов
make generate-proto

# Сборка сервера
make build

# Запуск тестов
make test

# Установка зависимостей
make deps
```

## Примеры клиентов

### HTTP-клиент
```bash
go run examples/http_client.go config.json http://localhost:8080
```

### gRPC-клиент
```bash
go run examples/grpc_client.go config.json localhost:9090
```

## Документация API

### HTTP API

#### POST /config/check

**Запрос:**
- Метод: POST
- Content-Type: application/octet-stream
- Тело: Сырые данные конфигурации (JSON или YAML)

**Ответ:**
- Статус: 200 OK
- Content-Type: application/json
- Тело: JSON-объект с находками и сводкой

**Ответы с ошибками:**
- 400 Bad Request: Неверный формат конфигурации или ошибка парсинга
- 500 Internal Server Error: Ошибка сервера при выполнении аудита

### gRPC API

#### AuditConfig

**Запрос:**
```protobuf
message AuditConfigRequest {
  bytes config_data = 1;
  string config_format = 2;
}
```

**Ответ:**
```protobuf
message AuditConfigResponse {
  repeated Finding findings = 1;
  Summary summary = 2;
}
```

#### GetServerInfo

**Запрос:**
```protobuf
message GetServerInfoRequest {
}
```

**Ответ:**
```protobuf
message ServerInfo {
  string version = 1;
  string service_name = 2;
}
```

## Разработка

### Структура проекта
```
├── cmd/
│   └── server/          # Точка входа сервера
├── internal/
│   ├── parser/         # Парсинг конфигураций
│   ├── reporter/       # Утилиты отчётности
│   ├── rules/          # Правила безопасности
│   └── servers/        # Реализации серверов
│       ├── httpserver/  # HTTP-сервер
│       └── grpc/        # gRPC-сервер
├── examples/           # Примеры клиентов
└── testdata/           # Тестовые файлы конфигураций
```

### Добавление новых правил

1. Создайте новое правило, реализующее интерфейс `Rule`
2. Зарегистрируйте правило при инициализации сервера
3. Добавьте тесты для нового правила
