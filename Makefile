.PHONY: all agentd agents release test race lint fmt clean

TARGET_OS ?= $(shell go env GOOS)
TARGET_ARCH ?= $(shell go env GOARCH)
TARGET_ARM ?=
CGO_ENABLED ?= 0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
OUTPUT ?= bin/agentd$(if $(filter windows,$(TARGET_OS)),.exe,)
SERVER_OUTPUT ?= bin/agents$(if $(filter windows,$(TARGET_OS)),.exe,)
DIST_DIR ?= dist

all: agentd agents

agentd:
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) $(if $(TARGET_ARM),GOARM=$(TARGET_ARM)) CGO_ENABLED=$(CGO_ENABLED) go build -mod=readonly -trimpath -ldflags="-s -w -X main.Version=$(VERSION)" -o $(OUTPUT) ./cmd/agentd

agents:
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) $(if $(TARGET_ARM),GOARM=$(TARGET_ARM)) CGO_ENABLED=$(CGO_ENABLED) go build -mod=readonly -trimpath -ldflags="-s -w -X main.Version=$(VERSION)" -o $(SERVER_OUTPUT) ./cmd/agents

release:
	bash scripts/build-release.sh --os $(TARGET_OS) --arch $(TARGET_ARCH) $(if $(TARGET_ARM),--goarm $(TARGET_ARM)) --version $(VERSION) --out $(DIST_DIR)

test:
	go test -mod=readonly ./...

race:
	go test -mod=readonly -race ./...

lint:
	@test -z "$$(gofmt -l .)" || (echo 'run make fmt'; exit 1)
	go vet -mod=readonly ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin dist
