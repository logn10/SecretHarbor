.PHONY: all build build-shb build-secretharbor test clean install man install-man

GOTOOLCHAIN ?= local
CGO_ENABLED ?= 0
BIN_DIR ?= bin
VERSION ?= 0.4.0-prod
LDFLAGS ?= -s -w -X github.com/secretharbor/secretharbor/internal/cli.Version=$(VERSION)
PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man

all: build test man

build: build-shb build-secretharbor

build-shb:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/shb ./cmd/shb
	@if [ "$$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then codesign -s - -f $(BIN_DIR)/shb; fi

build-secretharbor:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/secretharbor ./cmd/secretharbor
	@if [ "$$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then codesign -s - -f $(BIN_DIR)/secretharbor; fi

man:
	@mkdir -p man/man1
	GOTOOLCHAIN=$(GOTOOLCHAIN) go run ./cmd/gen-man man/man1

install-man: man
	@mkdir -p $(MANDIR)/man1
	cp man/man1/*.1 $(MANDIR)/man1/

test:
	GOTOOLCHAIN=$(GOTOOLCHAIN) go test -v ./...

clean:
	rm -rf $(BIN_DIR) man

install:
	GOTOOLCHAIN=$(GOTOOLCHAIN) go install -trimpath -ldflags="$(LDFLAGS)" ./cmd/shb
	GOTOOLCHAIN=$(GOTOOLCHAIN) go install -trimpath -ldflags="$(LDFLAGS)" ./cmd/secretharbor
