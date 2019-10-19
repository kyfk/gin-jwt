GO ?= go
GOFMT ?= gofmt "-s"
GOLINT ?= golint
PACKAGES ?= $(shell $(GO) list ./... | grep -v example)
GOFILES := $(shell find . -name "*.go" -type f)

.PHONY: fmt-check
fmt-check:
	@diff=$$($(GOFMT) -d $(GOFILES)); \
	if [ -n "$$diff" ]; then \
		echo "Please run 'make fmt' and commit the result:"; \
		echo "$${diff}"; \
		exit 1; \
	fi;

.PHONY: test
test: fmt-check
	@$(GO) test -v -cover -coverprofile coverage.txt $(PACKAGES) && echo "\n==>\033[32m Ok\033[m\n" || exit 1

.PHONY: vet
vet:
	$(GO) vet $(PACKAGES)

.PHONY: lint
lint:
	@hash revive > /dev/null 2>&1; if [ $$? -ne 0 ]; then \
		$(GO) get golang.org/x/lint/golint; \
	fi
	$(GOLINT) $(PACKAGES)

.PHONY: clean
clean:
	$(GO) clean -modcache -cache -i
	find . -name "coverage.txt" -delete
