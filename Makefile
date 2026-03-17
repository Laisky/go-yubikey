.PHONY: install
install:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: lint
lint:
	goimports -local github.com/Laisky/go-yubikey/v2 -w .
	go mod tidy
	gofmt -s -w .
	golangci-lint run
	govulncheck ./...

.PHONY: changelog
changelog:
	./.scripts/generate_changelog.sh
