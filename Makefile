# rbac developer tasks. Run `make help` for a list.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Development tools are pinned in tools/go.mod and run with `go tool`.
GOTOOL := go tool -modfile=tools/go.mod
# Keep local tests in the same mode as CI, even if go.mod's default changes.
export GODEBUG := fips140=only
# `make test` runs every test, and TESTFLAGS adds flags to go test, such as -json or -run.
# `make test SHARD=i/n` runs only the top-level tests of the ith of n shards, as CI does, placed by
# the times in TIMINGS, a file of `go test -json` output, where it is given; see CONTRIBUTING.md.
# Its -run comes after TESTFLAGS, so it replaces theirs.
# The flags the tests build with: shards select lists them built alike, so they build once.
TESTBUILD := -race -cover
GOTEST := go test $(TESTBUILD) -shuffle=on -timeout 30m

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: check
check: tidy-check lint vulncheck test ## Run all linters and tests

.PHONY: tidy-check
tidy-check: ## Verify both Go modules are tidy
	go mod tidy -diff
	cd tools && go mod tidy -diff

.PHONY: lint
lint: ## Lint Go
	$(GOTOOL) golangci-lint run ./...

.PHONY: vulncheck
vulncheck: ## Check Go dependencies for vulnerabilities
	$(GOTOOL) govulncheck ./...

.PHONY: test
test: ## Run the tests with race detection and coverage; SHARD=i/n runs one shard
ifdef SHARD
	run="$$(go run ./internal/shards select -shard '$(SHARD)' -timings '$(TIMINGS)' -- $(TESTBUILD) ./...)" && \
	$(GOTEST) $(TESTFLAGS) -run "$$run" ./...
else
	$(GOTEST) $(TESTFLAGS) ./...
endif
