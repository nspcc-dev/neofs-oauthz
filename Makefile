#!/usr/bin/make -f

REPO ?= $(shell go list -m)
VERSION ?= $(shell git describe --tags --dirty --match "v*" --always --abbrev=8 | sed 's/^v//' 2>/dev/null || cat VERSION 2>/dev/null || echo "develop")

HUB_IMAGE ?= nspccdev/neofs-oauthz
HUB_TAG ?= "$(shell echo ${VERSION})"

# List of binaries to build. For now just one.
BIN = bin
DIRS = $(BIN)

CMDS = $(notdir $(basename $(wildcard cmd/*)))
BINS = $(addprefix $(BIN)/, $(CMDS))

# Make all binaries
all: $(DIRS) $(BINS)

$(BINS): $(DIRS) dep
	@echo "⇒ Build $@"
	CGO_ENABLED=0 \
	GO111MODULE=on \
	go build -v -trimpath \
	-ldflags "-X main.Version=$(VERSION)" \
	-o $@ ./cmd/$(notdir $@)

$(DIRS):
	@echo "⇒ Ensure dir: $@"
	@mkdir -p $@

# Pull go dependencies
dep:
	@printf "⇒ Download requirements: "
	@CGO_ENABLED=0 \
	GO111MODULE=on \
	go mod download && echo OK
	@printf "⇒ Tidy requirements: "
	@CGO_ENABLED=0 \
	GO111MODULE=on \
	go mod tidy -v && echo OK

image:
	@echo "⇒ Build NeoFS OAuthz docker image "
	@docker build \
		--build-arg REPO=$(REPO) \
		--build-arg VERSION=$(VERSION) \
		--rm \
		-f Dockerfile \
		-t $(HUB_IMAGE):$(HUB_TAG) .

gh-docker-vars:
	@echo "file=Dockerfile"
	@echo "version=$(HUB_TAG)"
	@echo "repo=$(HUB_IMAGE)"

# Run tests
test:
	@go test ./... -cover

# Run tests with race detection and produce coverage output
cover:
	@go test -v -race ./... -coverprofile=coverage.txt -covermode=atomic
	@go tool cover -html=coverage.txt -o coverage.html

# Run all code formatters
fmts: fmt imports modernize

# Reformat code
fmt:
	@echo "⇒ Processing gofmt check"
	@GO111MODULE=on gofmt -s -w ./

# Reformat imports
imports:
	@echo "⇒ Processing goimports check"
	@GO111MODULE=on goimports -w ./

# Prettify code
modernize:
	@echo "⇒ Processing modernize check"
	@go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest -fix ./...

.golangci.yml:
	wget -O $@ https://github.com/nspcc-dev/.github/raw/master/.golangci.yml

# Run linters
lint: .golangci.yml
	@golangci-lint --timeout=5m run
