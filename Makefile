BINARY ?= acta
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_LICENSES ?= go-licenses
GORELEASER ?= goreleaser
LDFLAGS := -X github.com/nobbettt/acta/internal/version.Version=$(VERSION) -X github.com/nobbettt/acta/internal/version.Commit=$(COMMIT) -X github.com/nobbettt/acta/internal/version.Date=$(DATE)

.PHONY: build check clean fmt fmt-check lint publication-check release-notices release-notices-check release-snapshot test

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/acta

clean:
	rm -f $(BINARY)

fmt:
	gofmt -w cmd internal schemas scripts/validate-release-tag.go

fmt-check:
	test -z "$$(gofmt -l cmd internal schemas scripts/validate-release-tag.go)"

lint:
	golangci-lint run

release-notices:
	@set -eu; \
		tmp="THIRD_PARTY_NOTICES.tmp"; \
		trap 'rm -f "$$tmp"' EXIT; \
		goroot="$$(go env GOROOT)"; \
		go_license="$$goroot/LICENSE"; \
		if [ ! -f "$$go_license" ]; then go_license="$$(dirname "$$goroot")/LICENSE"; fi; \
		go_patents="$$goroot/PATENTS"; \
		if [ ! -f "$$go_patents" ]; then go_patents="$$(dirname "$$goroot")/PATENTS"; fi; \
		test -f "$$go_license"; \
		{ \
			printf '%s\n' \
				'Acta includes the following third-party software. Each component remains' \
				'subject to its own license terms.'; \
			printf '\n%s\n%s\n%s\n\n' \
				'================================================================================' \
				'Component: Go standard library' \
				'License: BSD-3-Clause'; \
			cat "$$go_license"; \
			if [ -f "$$go_patents" ]; then printf '\n'; cat "$$go_patents"; fi; \
			printf '\n'; \
			$(GO_LICENSES) report ./cmd/acta \
				--ignore github.com/nobbettt/acta \
				--template release/licenses.tpl; \
			bash release/module-notices.sh; \
		} > "$$tmp"; \
		mv "$$tmp" THIRD_PARTY_NOTICES; \
		trap - EXIT

release-notices-check: release-notices
	git diff --exit-code -- THIRD_PARTY_NOTICES

release-snapshot: release-notices-check
	$(GORELEASER) release --snapshot --clean

publication-check:
	go test ./internal/agents ./internal/runtimebundle ./internal/version ./schemas
	./scripts/public-snapshot-test.sh

test:
	go test ./...

check: fmt-check test build
