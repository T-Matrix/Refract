.PHONY: test build run

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -trimpath -o bin/refract ./cmd/gateway

run:
	go run ./cmd/gateway
