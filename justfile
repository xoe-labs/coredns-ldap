# use with https://github.com/casey/just

# fixe auto-fixable lint issues in staged files
fix:
	~/bin/pre-commit run go-returns  # fixes all Go lint issues
	~/bin/pre-commit run prettier    # fixes all Markdown (& other) lint issues

# lint most common issues in - or due - to staged files
lint:
	~/bin/pre-commit run go-vet-mod || true  # runs go vet
	~/bin/pre-commit run go-lint    || true  # runs golint
	~/bin/pre-commit run go-critic  || true  # runs gocritic

# lint all issues in - or due - to staged files
lint-all:
	~/bin/pre-commit run golangci-lint-mod || true  # runs golangci-lint

# run tests in - or due - to staged files
test:
	~/bin/pre-commit run go-test-mod || true  # runs go test

# commit skipping pre-commit hooks
commit m:
	git commit --no-verify -m "{{m}}"

# amend skipping pre-commit hooks
amend:
	git commit --amend --no-verify

# install/update code automation (prettier, pre-commit, goreturns, lintpack, gocritic, golangci-lint)
install:
	npm i -g prettier
	curl https://pre-commit.com/install-local.py | python3 -
	go get github.com/sqs/goreturns
	go get github.com/go-lintpack/lintpack/...
	go get github.com/go-critic/go-critic/...
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(shell go env GOPATH)/bin v1.27.0

# setup pre-commit hooks (optional)
setup:
	~/bin/pre-commit install --install-hooks
