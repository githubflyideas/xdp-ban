VERSION ?= v0.22
LDFLAGS := -s -w -X main.Version=$(VERSION)

CLANG   ?= clang
BPF_CFLAGS := -O2 -g -target bpf -Wall

DIST := dist

# 三个二进制:控制面 xdp-ban + 数据面 xdp-agent / xdp-sampler
.PHONY: all
all: bpf build

## bpf: 编译 eBPF 目标文件并放到各自的 embed 目录
.PHONY: bpf
bpf:
	$(CLANG) $(BPF_CFLAGS) -c bpf/xdp_filter.c   -o cmd/xdp-agent/obj/xdp_filter.o
	$(CLANG) $(BPF_CFLAGS) -c bpf/xdp_sampler.c  -o cmd/xdp-sampler/obj/xdp_sampler.o

## build: 编译三个纯 Go 静态二进制到当前目录
.PHONY: build
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o xdp-ban     ./cmd/xdpban
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o xdp-agent   ./cmd/xdp-agent
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o xdp-sampler ./cmd/xdp-sampler

## dist: 交叉编译 linux/amd64 + linux/arm64 到 dist/,并打校验和
.PHONY: dist
dist:
	@mkdir -p $(DIST)
	@for arch in amd64 arm64; do \
	  echo ">> building linux/$$arch"; \
	  for cmd in xdpban:xdp-ban xdp-agent:xdp-agent xdp-sampler:xdp-sampler; do \
	    pkg=$${cmd%%:*}; out=$${cmd##*:}; \
	    CGO_ENABLED=0 GOOS=linux GOARCH=$$arch \
	      go build -trimpath -ldflags "$(LDFLAGS)" \
	      -o $(DIST)/$$out-linux-$$arch ./cmd/$$pkg; \
	  done; \
	done
	@cd $(DIST) && sha256sum * > SHA256SUMS
	@echo ">> dist artifacts:" && ls -lh $(DIST)

## test: 全量单元测试(含竞态检测)
.PHONY: test
test:
	CGO_ENABLED=1 go test -race ./...

## bench: 运行基准测试(含内存分配统计)
.PHONY: bench
bench:
	go test -bench=. -benchmem -run='^$$' ./...

## fuzz: 对信任边界的解析函数各跑 30s 模糊测试
.PHONY: fuzz
fuzz:
	go test -run='^$$' -fuzz='^FuzzParseTarget$$' -fuzztime=30s ./cmd/xdp-agent/
	go test -run='^$$' -fuzz='^FuzzParseRate$$'   -fuzztime=30s ./internal/web/

## prof: 采集 TopFlows 热路径的 CPU/内存 profile 到 dist/prof/
.PHONY: prof
prof:
	@mkdir -p $(DIST)/prof
	go test -bench=BenchmarkTopFlows -run='^$$' \
	  -cpuprofile=$(DIST)/prof/cpu.out \
	  -memprofile=$(DIST)/prof/mem.out ./internal/web/
	@echo "分析: go tool pprof -http=:0 $(DIST)/prof/cpu.out"

## cover: 生成覆盖率报告
.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

## vet: 静态检查
.PHONY: vet
vet:
	go vet ./...

## check: 提交前一把梭
.PHONY: check
check: vet test

.PHONY: run
run: build
	./xdp-ban

.PHONY: clean
clean:
	rm -f xdp-ban xdp-agent xdp-sampler coverage.out coverage.html *.db
	rm -rf $(DIST)
	rm -f cmd/xdp-agent/obj/*.o cmd/xdp-sampler/obj/*.o
