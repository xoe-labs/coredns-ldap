# use with https://github.com/casey/just

# use pre-commit manual stage
pre-commit-manual := "pre-commit run --hook-stage manual"

# fix auto-fixable lint issues in staged files
fix:
	{{ pre-commit-manual }} go-returns-write  # fixes all Go lint issues
	{{ pre-commit-manual }} prettier          # fixes all Markdown (& other) lint issues

# lint issues in - or due - to staged files
lint:
	{{ pre-commit-manual }} go-vet-mod-changed         # first run go vet
	{{ pre-commit-manual }} go-lint-changed            # then run golint
	{{ pre-commit-manual }} golangci-lint-mod-changed  # last run golangci-lint

# lint all issues
lint-all:
	{{ pre-commit-manual }} golangci-lint-repo-mod-all || true  # runs golangci-lint

# run tests in - or due - to staged files
test:
	{{ pre-commit-manual }} go-test-repo-mod-all || true  # runs go test

# push skipping pre-push hooks
push:
	git push --no-verify

# install/update code automation
install:
	curl https://pre-commit.com/install-local.py | python3 -
	pre-commit install-hooks
	# are NOT (yet) automatically installed
	# through https://github.com/tekwizely/pre-commit-golang
	go get github.com/sqs/goreturns
	go get github.com/go-lintpack/lintpack/...
	go get github.com/go-critic/go-critic/...
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(go env GOPATH)/bin v1.27.0

# setup hooks for stage (optional)
setup stage="pre-push":
	pre-commit install --hook-type {{ stage }}  # uninstall: `pre-commit uninstall`
