.PHONY: all agentd fips release test race lint fmt clean

TARGET_OS ?= $(shell go env GOOS)
TARGET_ARCH ?= $(shell go env GOARCH)
TARGET_ARM ?=
CGO_ENABLED ?= 0
VERSION ?= dev-$(shell git rev-parse --short HEAD 2>/dev/null || echo local)
FIPS ?= false
FIPS_VERSION := v1.0.0-c2097c7c
GO_FIPS_MODE := $(if $(filter true,$(FIPS)),$(FIPS_VERSION),off)
OUTPUT ?= bin/agentd$(if $(filter true,$(FIPS)),-fips,)$(if $(filter windows,$(TARGET_OS)),.exe,)
DIST_DIR ?= dist
NFPM ?= nfpm

all: agentd

agentd:
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) $(if $(TARGET_ARM),GOARM=$(TARGET_ARM)) CGO_ENABLED=$(CGO_ENABLED) GOFIPS140=$(GO_FIPS_MODE) go build -mod=readonly -trimpath -ldflags="-s -w -X main.Version=$(VERSION)" -o $(OUTPUT) ./cmd/agentd
ifeq ($(FIPS),true)
	python3 scripts/release.py verify-fips --binary $(OUTPUT)
endif

fips:
	$(MAKE) agentd FIPS=true TARGET_OS=linux TARGET_ARCH=amd64 OUTPUT=bin/agentd-fips-linux-amd64

release:
ifeq ($(TARGET_OS),windows)
	pwsh -NoProfile -File scripts/build-windows.ps1 -Architecture $(TARGET_ARCH) -Version $(VERSION) -OutDir $(DIST_DIR)
else
	bash scripts/build-release.sh --os $(TARGET_OS) --arch $(TARGET_ARCH) $(if $(TARGET_ARM),--goarm $(TARGET_ARM)) $(if $(filter true,$(FIPS)),--fips) --version $(VERSION) --out $(DIST_DIR) --nfpm $(NFPM)
endif

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
