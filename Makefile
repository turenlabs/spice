SHELL := /bin/bash

APP_NAME := spice
VERSION ?= $(shell if [[ -f VERSION ]]; then tr -d '[:space:]' < VERSION; else sed -n 's/.*"productVersion": "\([^"]*\)".*/\1/p' wails.json | head -n1; fi)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf "unknown")
APP_BUNDLE := build/bin/$(APP_NAME).app
INSTALL_DIR ?= /Applications
CLI_INSTALL_DIR ?= $(HOME)/.local/bin
CLI_BIN := build/bin/$(APP_NAME)
DIST_DIR ?= dist
CLI_PLATFORMS ?= darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
GO_BUILD_FLAGS ?= -trimpath
GO_LDFLAGS ?= -s -w
WAILS ?= $(shell command -v wails 2>/dev/null || printf "%s/go/bin/wails" "$(HOME)")

.PHONY: help deps frontend-install frontend-build test build build-cli install install-cli dev version release-check release release-artifacts release-cli package-app checksums clean
.NOTPARALLEL: release release-artifacts

help:
	@printf "Spice developer targets\n\n"
	@printf "  make deps              Install frontend dependencies\n"
	@printf "  make test              Run Go tests and frontend production build\n"
	@printf "  make build             Build the Wails desktop app\n"
	@printf "  make build-cli         Build the standalone CLI binary\n"
	@printf "  make release-check     Validate release metadata and required tools\n"
	@printf "  make release           Build release archives and SHA-256 checksums\n"
	@printf "  make release-cli       Build CLI archives for $(CLI_PLATFORMS)\n"
	@printf "  make package-app       Zip the built macOS app bundle when present\n"
	@printf "  make checksums         Write $(DIST_DIR)/SHA256SUMS\n"
	@printf "  make install           Build and install $(APP_NAME).app to $(INSTALL_DIR)\n"
	@printf "  make install-cli       Build and install CLI to $(CLI_INSTALL_DIR)\n"
	@printf "  make dev               Start Wails dev mode\n"
	@printf "  make clean             Remove local build outputs\n"
	@printf "\nRelease metadata: $(APP_NAME) $(VERSION) ($(COMMIT))\n"

deps: frontend-install
	go mod download

frontend-install:
	cd frontend && npm install

frontend-build:
	cd frontend && npm run build

test: frontend-build
	go test ./...

build: test
	$(WAILS) build

build-cli: frontend-build
	mkdir -p build/bin
	go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o $(CLI_BIN) .

install: build
	@if [[ "$$(uname -s)" != "Darwin" ]]; then \
		printf "make install currently installs the macOS app bundle only. Use make build-cli or make install-cli on this platform.\n"; \
		exit 1; \
	fi
	rm -rf "$(INSTALL_DIR)/$(APP_NAME).app"
	cp -R "$(APP_BUNDLE)" "$(INSTALL_DIR)/$(APP_NAME).app"
	@printf "Installed $(INSTALL_DIR)/$(APP_NAME).app\n"

install-cli: build-cli
	mkdir -p "$(CLI_INSTALL_DIR)"
	cp "$(CLI_BIN)" "$(CLI_INSTALL_DIR)/$(APP_NAME)"
	chmod +x "$(CLI_INSTALL_DIR)/$(APP_NAME)"
	@printf "Installed $(CLI_INSTALL_DIR)/$(APP_NAME)\n"

dev:
	$(WAILS) dev

version:
	@printf "%s %s (%s)\n" "$(APP_NAME)" "$(VERSION)" "$(COMMIT)"

release-check:
	@test -n "$(VERSION)" || { printf "VERSION is empty. Set VERSION or add a VERSION file.\n" >&2; exit 1; }
	@wails_version="$$(sed -n 's/.*"productVersion": "\([^"]*\)".*/\1/p' wails.json | head -n1)"; \
	if [[ -n "$$wails_version" && "$$wails_version" != "$(VERSION)" ]]; then \
		printf "VERSION (%s) does not match wails.json productVersion (%s).\n" "$(VERSION)" "$$wails_version" >&2; \
		exit 1; \
	fi
	@command -v go >/dev/null || { printf "go is required.\n" >&2; exit 1; }
	@command -v npm >/dev/null || { printf "npm is required for frontend assets.\n" >&2; exit 1; }
	@command -v shasum >/dev/null || { printf "shasum is required for checksums.\n" >&2; exit 1; }
	@printf "Release metadata OK: $(APP_NAME) $(VERSION) ($(COMMIT))\n"

release: test release-artifacts checksums
	@printf "Release artifacts written to $(DIST_DIR)\n"

release-artifacts: release-cli package-app

release-cli: release-check frontend-build
	rm -rf "$(DIST_DIR)"
	mkdir -p "$(DIST_DIR)"
	@set -euo pipefail; \
	for platform in $(CLI_PLATFORMS); do \
		goos="$${platform%/*}"; \
		goarch="$${platform#*/}"; \
		archive="$(APP_NAME)_$(VERSION)_$${goos}_$${goarch}"; \
		workdir="$(DIST_DIR)/$$archive"; \
		mkdir -p "$$workdir"; \
		printf "Building $$archive\n"; \
		GOOS="$$goos" GOARCH="$$goarch" go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o "$$workdir/$(APP_NAME)" .; \
		cp README.md SECURITY.md "$$workdir/"; \
		tar -C "$(DIST_DIR)" -czf "$(DIST_DIR)/$$archive.tar.gz" "$$archive"; \
		rm -rf "$$workdir"; \
	done

package-app: build
	@if [[ -d "$(APP_BUNDLE)" ]]; then \
		mkdir -p "$(DIST_DIR)"; \
		archive="$(APP_NAME)_$(VERSION)_macos_app.zip"; \
		printf "Packaging $$archive\n"; \
		cd "$$(dirname "$(APP_BUNDLE)")" && zip -qry "../../$(DIST_DIR)/$$archive" "$$(basename "$(APP_BUNDLE)")"; \
	else \
		printf "Skipping app package: $(APP_BUNDLE) does not exist. Run make build first.\n"; \
	fi

checksums:
	@test -d "$(DIST_DIR)" || { printf "$(DIST_DIR) does not exist.\n" >&2; exit 1; }
	@tmpfile="$$(mktemp)"; \
	find "$(DIST_DIR)" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > "$$tmpfile"; \
	mv "$$tmpfile" "$(DIST_DIR)/SHA256SUMS"; \
	printf "Wrote $(DIST_DIR)/SHA256SUMS\n"

clean:
	rm -rf build/bin frontend/dist "$(DIST_DIR)"
