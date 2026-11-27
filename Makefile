# Gatecrasher: every entry point. GNU make on Linux, macOS and Windows (Git Bash).
GO      ?= go
BIN     := bin/gatecrasher
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/yarrasatwik/gatecrasher/internal/app.Version=$(VERSION)

.PHONY: install build hooks lab-up lab-seed lab-reset lab-down lab-nuke shop audit fix-all watch serve parity test test-lab check demo

install: hooks build
	@command -v flagsmith >/dev/null 2>&1 || echo "optional: install the Flagsmith CLI v2 (curl -fsSL https://get.flagsmith.com | sh) to apply fixes through it"

build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/gatecrasher

hooks:
	git config core.hooksPath .githooks

lab-up: build
	$(BIN) lab up

lab-seed: build
	$(BIN) lab seed

lab-reset: build
	$(BIN) lab reset

lab-down: build
	$(BIN) lab down

lab-nuke: build
	$(BIN) lab nuke

shop:
	$(GO) run ./lab/shop

audit: build
	$(BIN) audit

fix-all: build
	$(BIN) fix-all

watch: build
	$(BIN) watch

serve: build
	$(BIN) serve --watch

parity: build
	$(BIN) parity -n 1000

test:
	$(GO) test -count=1 ./...

test-lab:
	$(GO) test -tags lab -count=1 -timeout 20m -v ./tests/integration/...

check:
	@test -z "$$(gofmt -l cmd internal lab tests)" || (gofmt -l cmd internal lab tests; exit 1)
	$(GO) vet ./...
	$(GO) vet -tags lab ./tests/...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
	$(GO) test -count=1 ./...

demo: build
	bash scripts/demo.sh
