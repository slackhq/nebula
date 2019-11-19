BUILD_NUMBER ?= dev+$(shell date -u '+%Y%m%d%H%M%S')
GO111MODULE = on
export GO111MODULE

all:
	make bin
	make bin-arm
	make bin-arm6
	make bin-arm64
	make bin-darwin
	make bin-windows

bin:
	go build -ldflags "-X main.Build=$(BUILD_NUMBER)" -o ./nebula ./cmd/nebula
	go build -ldflags "-X main.Build=$(BUILD_NUMBER)" -o ./nebula-cert ./cmd/nebula-cert

install:
	go install -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula
	go install -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula-cert

bin-arm:
	GOARCH=arm GOOS=linux go build -o nebula-arm -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula

bin-arm6:
	GOARCH=arm GOARM=6 GOOS=linux go build -o nebula-arm6 -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula

bin-arm64:
	GOARCH=arm64 GOOS=linux go build -o nebula-arm64 -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula


bin-vagrant:
	GOARCH=amd64 GOOS=linux go build -o nebula -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula
	GOARCH=amd64 GOOS=linux go build -ldflags "-X main.Build=$(BUILD_NUMBER)" -o ./nebula-cert ./cmd/nebula-cert
bin-darwin:
	GOARCH=amd64 GOOS=darwin go build -o nebula-darwin -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula

bin-windows:
	GOARCH=amd64 GOOS=windows go build -o nebula.exe -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula

bin-linux:
	GOARCH=amd64 GOOS=linux go build -o ./nebula -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula
	GOARCH=amd64 GOOS=linux go build -o ./nebula-cert -ldflags "-X main.Build=$(BUILD_NUMBER)" ./cmd/nebula-cert

vet:
	go vet -v ./...

test:
	go test -v ./...

test-cov-html:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=.

bench-cpu:
	go test -bench=. -benchtime=5s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

bench-cpu-long:
	go test -bench=. -benchtime=60s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

proto: nebula.pb.go cert/cert.pb.go

nebula.pb.go: nebula.proto .FORCE
	go build github.com/golang/protobuf/protoc-gen-go
	PATH="$(PWD):$(PATH)" protoc --go_out=. $<
	rm protoc-gen-go

cert/cert.pb.go: cert/cert.proto .FORCE
	$(MAKE) -C cert cert.pb.go

.FORCE:
.PHONY: test test-cov-html bench bench-cpu bench-cpu-long bin proto
.DEFAULT_GOAL := bin
