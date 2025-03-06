NEBULA_CMD_PATH = "./cmd/nebula"
CGO_ENABLED = 0
export CGO_ENABLED

# Set up OS specific bits
ifeq ($(OS),Windows_NT)
	NEBULA_CMD_SUFFIX = .exe
	NULL_FILE = nul
	# RIO on windows does pointer stuff that makes go vet angry
	VET_FLAGS = -unsafeptr=false
else
	NEBULA_CMD_SUFFIX =
	NULL_FILE = /dev/null
endif

# Only defined the build number if we haven't already
ifndef BUILD_NUMBER
	ifeq ($(shell git describe --exact-match 2>$(NULL_FILE)),)
		BUILD_NUMBER = $(shell git describe --abbrev=0 --match "v*" | cut -dv -f2)-$(shell git branch --show-current)-$(shell git describe --long --dirty | cut -d- -f2-)
	else
		BUILD_NUMBER = $(shell git describe --exact-match --dirty | cut -dv -f2)
	endif
endif

DOCKER_IMAGE_REPO ?= nebulaoss/nebula
DOCKER_IMAGE_TAG ?= latest

LDFLAGS = -X main.Build=$(BUILD_NUMBER)

ALL_LINUX = linux-amd64 \
	linux-386 \
	linux-ppc64le \
	linux-arm-5 \
	linux-arm-6 \
	linux-arm-7 \
	linux-arm64 \
	linux-mips \
	linux-mipsle \
	linux-mips64 \
	linux-mips64le \
	linux-mips-softfloat \
	linux-riscv64 \
	linux-loong64

ALL_FREEBSD = freebsd-amd64 \
	freebsd-arm64

ALL_OPENBSD = openbsd-amd64 \
	openbsd-arm64

ALL_NETBSD = netbsd-amd64 \
 	netbsd-arm64

ALL = $(ALL_LINUX) \
	$(ALL_FREEBSD) \
	$(ALL_OPENBSD) \
	$(ALL_NETBSD) \
	darwin-amd64 \
	darwin-arm64 \
	windows-amd64 \
	windows-arm64

e2e:
	$(TEST_ENV) go test -tags=e2e_testing -count=1 $(TEST_FLAGS) ./e2e

e2ev: TEST_FLAGS += -v
e2ev: e2e

e2evv: TEST_ENV += TEST_LOGS=1
e2evv: e2ev

e2evvv: TEST_ENV += TEST_LOGS=2
e2evvv: e2ev

e2evvvv: TEST_ENV += TEST_LOGS=3
e2evvvv: e2ev

e2e-bench: TEST_FLAGS = -bench=. -benchmem -run=^$
e2e-bench: e2e

DOCKER_BIN = build/linux-amd64/nebula build/linux-amd64/nebula-cert

all: $(ALL:%=build/%/nebula) $(ALL:%=build/%/nebula-cert)

docker: docker/linux-$(shell go env GOARCH)

release: $(ALL:%=build/nebula-%.tar.gz)

release-linux: $(ALL_LINUX:%=build/nebula-%.tar.gz)

release-freebsd: $(ALL_FREEBSD:%=build/nebula-%.tar.gz)

release-openbsd: $(ALL_OPENBSD:%=build/nebula-%.tar.gz)

release-netbsd: $(ALL_NETBSD:%=build/nebula-%.tar.gz)

release-boringcrypto: build/nebula-linux-$(shell go env GOARCH)-boringcrypto.tar.gz

BUILD_ARGS += -trimpath

bin-windows: build/windows-amd64/nebula.exe build/windows-amd64/nebula-cert.exe
	mv $? .

bin-windows-arm64: build/windows-arm64/nebula.exe build/windows-arm64/nebula-cert.exe
	mv $? .

bin-darwin: build/darwin-amd64/nebula build/darwin-amd64/nebula-cert
	mv $? .

bin-freebsd: build/freebsd-amd64/nebula build/freebsd-amd64/nebula-cert
	mv $? .

bin-freebsd-arm64: build/freebsd-arm64/nebula build/freebsd-arm64/nebula-cert
	mv $? .

bin-boringcrypto: build/linux-$(shell go env GOARCH)-boringcrypto/nebula build/linux-$(shell go env GOARCH)-boringcrypto/nebula-cert
	mv $? .

bin-pkcs11: BUILD_ARGS += -tags pkcs11
bin-pkcs11: CGO_ENABLED = 1
bin-pkcs11: bin

bin:
	go build $(BUILD_ARGS) -ldflags "$(LDFLAGS)" -o ./nebula${NEBULA_CMD_SUFFIX} ${NEBULA_CMD_PATH}
	go build $(BUILD_ARGS) -ldflags "$(LDFLAGS)" -o ./nebula-cert${NEBULA_CMD_SUFFIX} ./cmd/nebula-cert

install:
	go install $(BUILD_ARGS) -ldflags "$(LDFLAGS)" ${NEBULA_CMD_PATH}
	go install $(BUILD_ARGS) -ldflags "$(LDFLAGS)" ./cmd/nebula-cert

build/linux-arm-%: GOENV += GOARM=$(word 3, $(subst -, ,$*))
build/linux-mips-%: GOENV += GOMIPS=$(word 3, $(subst -, ,$*))

# Build an extra small binary for mips-softfloat
build/linux-mips-softfloat/%: LDFLAGS += -s -w

# boringcrypto
build/linux-amd64-boringcrypto/%: GOENV += GOEXPERIMENT=boringcrypto CGO_ENABLED=1
build/linux-arm64-boringcrypto/%: GOENV += GOEXPERIMENT=boringcrypto CGO_ENABLED=1
build/linux-amd64-boringcrypto/%: LDFLAGS += -checklinkname=0
build/linux-arm64-boringcrypto/%: LDFLAGS += -checklinkname=0

build/%/nebula: .FORCE
	GOOS=$(firstword $(subst -, , $*)) \
		GOARCH=$(word 2, $(subst -, ,$*)) $(GOENV) \
		go build $(BUILD_ARGS) -o $@ -ldflags "$(LDFLAGS)" ${NEBULA_CMD_PATH}

build/%/nebula-cert: .FORCE
	GOOS=$(firstword $(subst -, , $*)) \
		GOARCH=$(word 2, $(subst -, ,$*)) $(GOENV) \
		go build $(BUILD_ARGS) -o $@ -ldflags "$(LDFLAGS)" ./cmd/nebula-cert

build/%/nebula.exe: build/%/nebula
	mv $< $@

build/%/nebula-cert.exe: build/%/nebula-cert
	mv $< $@

build/nebula-%.tar.gz: build/%/nebula build/%/nebula-cert
	tar -zcv -C build/$* -f $@ nebula nebula-cert

build/nebula-%.zip: build/%/nebula.exe build/%/nebula-cert.exe
	cd build/$* && zip ../nebula-$*.zip nebula.exe nebula-cert.exe

docker/%: build/%/nebula build/%/nebula-cert
	docker build . $(DOCKER_BUILD_ARGS) -f docker/Dockerfile --platform "$(subst -,/,$*)" --tag "${DOCKER_IMAGE_REPO}:${DOCKER_IMAGE_TAG}" --tag "${DOCKER_IMAGE_REPO}:$(BUILD_NUMBER)"

vet:
	go vet $(VET_FLAGS) -v ./...

test:
	go test -v ./...

test-boringcrypto:
	GOEXPERIMENT=boringcrypto CGO_ENABLED=1 go test -ldflags "-checklinkname=0" -v ./...

test-pkcs11:
	CGO_ENABLED=1 go test -v -tags pkcs11 ./...

test-cov-html:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

build-test-mobile:
	GOARCH=amd64 GOOS=ios go build $(shell go list ./... | grep -v '/cmd/\|/examples/')
	GOARCH=arm64 GOOS=ios go build $(shell go list ./... | grep -v '/cmd/\|/examples/')
	GOARCH=amd64 GOOS=android go build $(shell go list ./... | grep -v '/cmd/\|/examples/')
	GOARCH=arm64 GOOS=android go build $(shell go list ./... | grep -v '/cmd/\|/examples/')

bench:
	go test -bench=.

bench-cpu:
	go test -bench=. -benchtime=5s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

bench-cpu-long:
	go test -bench=. -benchtime=60s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

proto: nebula.pb.go cert/cert_v1.pb.go

nebula.pb.go: nebula.proto .FORCE
	go build github.com/gogo/protobuf/protoc-gen-gogofaster
	PATH="$(CURDIR):$(PATH)" protoc --gogofaster_out=paths=source_relative:. $<
	rm protoc-gen-gogofaster

cert/cert.pb.go: cert/cert.proto .FORCE
	$(MAKE) -C cert cert.pb.go

service:
	@echo > $(NULL_FILE)
	$(eval NEBULA_CMD_PATH := "./cmd/nebula-service")
ifeq ($(words $(MAKECMDGOALS)),1)
	@$(MAKE) service ${.DEFAULT_GOAL} --no-print-directory
endif

bin-docker: bin build/linux-amd64/nebula build/linux-amd64/nebula-cert

smoke-docker: bin-docker
	cd .github/workflows/smoke/ && ./build.sh
	cd .github/workflows/smoke/ && ./smoke.sh
	cd .github/workflows/smoke/ && NAME="smoke-p256" CURVE="P256" ./build.sh
	cd .github/workflows/smoke/ && NAME="smoke-p256" ./smoke.sh

smoke-relay-docker: bin-docker
	cd .github/workflows/smoke/ && ./build-relay.sh
	cd .github/workflows/smoke/ && ./smoke-relay.sh

smoke-docker-race: BUILD_ARGS = -race
smoke-docker-race: CGO_ENABLED = 1
smoke-docker-race: smoke-docker

smoke-vagrant/%: bin-docker build/%/nebula
	cd .github/workflows/smoke/ && ./build.sh $*
	cd .github/workflows/smoke/ && ./smoke-vagrant.sh $*

.FORCE:
.PHONY: bench bench-cpu bench-cpu-long bin build-test-mobile e2e e2ev e2evv e2evvv e2evvvv proto release service smoke-docker smoke-docker-race test test-cov-html smoke-vagrant/%
.DEFAULT_GOAL := bin
