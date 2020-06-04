# use with https://github.com/casey/just

# fixe auto-fixable lint issues in all files
fix:
	~/bin/pre-commit run go-returns  # fixes all Go lint issues
	~/bin/pre-commit run prettier    # fixes all Markdown (& other) lint issues

# lint most common issues in all files
lint:
	~/bin/pre-commit run go-vet-mod || true  # runs go vet
	~/bin/pre-commit run go-lint    || true  # runs golint
	~/bin/pre-commit run go-critic  || true  # runs gocritic

# lint all issues in all files through meta linter
lint-all:
	~/bin/pre-commit run golangci-lint-mod || true  # runs golangci-lint on the module level

# commit skipping pre-commit hooks
commit m:
	git commit --no-verify -m "{{m}}"

# amend skipping pre-commit hooks
amend:
	git commit --amend --no-verify

# install / update code automation tools (prettier, pre-commit, goreturns)
setup:
	npm i -g prettier
	curl https://pre-commit.com/install-local.py | python3 -
	~/bin/pre-commit install --install-hooks
	go get github.com/sqs/goreturns
