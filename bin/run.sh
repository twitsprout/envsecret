#!/usr/bin/env sh

set -euxo pipefail

# lint
golangci-lint run

# test
go test -p 1 -covermode=atomic -timeout=30s ./...
