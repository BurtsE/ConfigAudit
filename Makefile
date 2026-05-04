.PHONY: build clean generate-proto

generate-proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		./proto/config_audit.proto

build:
	go build -o bin/config-audit ./cmd/config-audit
	go build -o bin/http_server ./cmd/server
	go build -o bin/grpc_client ./examples/grpc_client.go
	go build -o bin/http_client ./examples/http_client.go

clean:
	rm -rf bin/

test:
	go test ./...

deps:
	go mod tidy