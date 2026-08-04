BINARY=xdp-ban
VERSION?=v0.22

build:
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BINARY) ./cmd/xdpban

test:
	go test -v -race -coverprofile=coverage.out ./internal/...

coverage: test
	go tool cover -html=coverage.out -o coverage.html

run: build
	./$(BINARY)

docker-build:
	docker build -t xdpban:$(VERSION) .

clean:
	rm -f $(BINARY) *.db coverage.out coverage.html

dev:
	CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)-dev" -o $(BINARY) ./cmd/xdpban && ./$(BINARY)

.PHONY: build test run clean docker-build coverage dev
