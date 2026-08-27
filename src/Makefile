PROTOC_GEN_GO_VERSION ?= v1.36.12
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.2
PROTO_TOOLS_DIR := $(CURDIR)/.tools/bin

.PHONY: build run generate test test-race vet fmt check

build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/sws-lab ./cmd/sws-lab

run:
	go run -buildvcs=false ./cmd/sws-lab

generate:
	mkdir -p $(PROTO_TOOLS_DIR)
	GOBIN=$(PROTO_TOOLS_DIR) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(PROTO_TOOLS_DIR) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	PATH=$(PROTO_TOOLS_DIR):$$PATH protoc --proto_path=. --go_out=. --go_opt=module=sws-lab --go-grpc_out=. --go-grpc_opt=module=sws-lab api/sws/lab/v1/lab.proto
	gofmt -w internal/gen/sws/lab/v1/*.go

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd/grpc-check/*.go cmd/sws-lab/*.go internal/grpclab/*.go internal/lab/*.go

check: test vet
