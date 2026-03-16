GO ?= go
BINARY ?= bhyakugan
CMD_DIR := ./cmd/bhyakugan
VERSION ?= 4.0.0
LDFLAGS ?= -X main.version=$(VERSION)

.PHONY: build test fmt vet

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_DIR)

test:
	$(GO) test ./internal/...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./cmd/bhyakugan ./internal/...
