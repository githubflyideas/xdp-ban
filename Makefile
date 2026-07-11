BINARY=xdp-ban
build:
	CGO_ENABLED=0 go build -ldflags "-s -w" -o $(BINARY) ./cmd/xdpban
test:
	go test ./internal/...
run: build
	./$(BINARY)
clean:
	rm -f $(BINARY) *.db
.PHONY: build test run clean
