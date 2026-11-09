# agentd: common tasks. `make help` lists them.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X agentd/internal/control.Version=$(VERSION) -X agentd/internal/relay.Version=$(VERSION) -X agentd/internal/agent.Version=$(VERSION)
GO ?= go
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: help all gen web build test test-short vet fmt dist docker helm-lint dev-db

help: ## show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

all: gen web build ## generate code, build the console and the binaries

gen: ## regenerate protobuf and admin API code
	$(GO) run ./tools/protogen
	cd internal/adminapi && $(GO) tool oapi-codegen -config oapi-codegen.yaml ../../docs/agentserver-openapi.yaml

web: ## build the web console (types and UI metadata come from the OpenAPI document)
	cd web && pnpm install --frozen-lockfile && pnpm build

build: ## build agentserver, agentrelay and agentd into bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/agentserver ./cmd/agentrelay ./cmd/agentd

test: ## run all tests (embedded PostgreSQL, or AGENTD_TEST_DATABASE_URL)
	AGENTD_REQUIRE_POSTGRES=1 $(GO) test -race -count=1 ./...

test-short: ## run the tests; database tests skip without PostgreSQL
	$(GO) test -count=1 ./...

vet: ## go vet and gofmt check
	$(GO) vet ./...
	@test -z "$$(gofmt -l cmd internal tools web/embed.go)" || (gofmt -l cmd internal tools web/embed.go; exit 1)

fmt: ## gofmt everything
	gofmt -w cmd internal tools web/embed.go

dist: ## cross-compile all binaries into dist/
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  for c in agentd agentserver agentrelay; do \
	    echo "dist/$$c-$$os-$$arch$$ext"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$c-$$os-$$arch$$ext ./cmd/$$c || exit 1; \
	  done; \
	done

docker: ## build the three images
	for t in agentserver agentrelay agentd; do docker build --target $$t --build-arg VERSION=$(VERSION) -t agentd/$$t:$(VERSION) . || exit 1; done

helm-lint: ## lint and render the chart
	helm lint deploy/helm/agentd
	helm template test deploy/helm/agentd > /dev/null

dev-db: ## run a local PostgreSQL on :55432 (data in .dev/pg)
	$(GO) run ./tools/devpg -port 55432 -data .dev/pg
