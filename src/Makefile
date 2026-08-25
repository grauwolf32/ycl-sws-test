.PHONY: build run test test-race vet fmt check

build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/sws-lab ./cmd/sws-lab

run:
	go run -buildvcs=false ./cmd/sws-lab

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd/sws-lab/*.go internal/lab/*.go

check: test vet
