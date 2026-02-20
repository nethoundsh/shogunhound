.PHONY: build test lint clean release-check

build:
	go build -ldflags "-X main.version=$$(git describe --tags --always --dirty)" -o shogunhound ./cmd/server

test:
	go test ./...

lint:
	golangci-lint run

clean:
	rm -f shogunhound

release-check:
	@echo "==> vet"; go vet ./...
	@echo "==> test"; go test ./...
	@echo "==> build linux/amd64"; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/server
	@echo "==> build linux/arm64"; CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/server
	@echo "All checks passed."
