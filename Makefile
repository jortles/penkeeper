# Penkeeper — build & run helpers
#
#   make            # build the server binary (embedded frontend)
#   make cli        # build the pk CLI into ./pk
#   make run        # build + run the server (auto-loads .env)
#   make install    # install the pk CLI to /usr/local/bin (needs sudo)
#   make setup      # first-time setup (DB + .env + binaries) via setup.sh
#   make fmt        # gofmt all Go sources
#   make vet        # go vet
#   make tidy       # go mod tidy
#   make clean      # remove built binaries

GO         ?= go
LDFLAGS    := -s -w
BUILDFLAGS := -ldflags="$(LDFLAGS)" -trimpath
PREFIX     ?= /usr/local

export CGO_ENABLED := 0

.PHONY: all server cli run install setup fmt vet tidy clean

all: server

server:
	$(GO) build $(BUILDFLAGS) -o ./server ./cmd/server

cli:
	$(GO) build $(BUILDFLAGS) -o ./pk ./cmd/pk

run: server
	./server

install: cli
	install -m 0755 ./pk $(PREFIX)/bin/pk
	@echo "Installed pk to $(PREFIX)/bin/pk"

setup:
	sudo ./setup.sh

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -f ./server ./pk
