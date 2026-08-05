VERSION ?= v0.27
LDFLAGS := -s -w -X main.Version=$(VERSION)

CLANG   ?= clang
# eBPF 编译参数。
# -I/usr/include/$(ARCH_TRIPLET) 是必须的:linux/types.h 会 include <asm/types.h>,
# 而 Debian/Ubuntu 把 asm/ 放在架构子目录下,不加这个 include 路径会
# "asm/types.h not found"。
ARCH_TRIPLET ?= $(shell gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)
BPF_CFLAGS := -O2 -g -target bpf -Wall -D__TARGET_ARCH_x86 \
              -I/usr/include/$(ARCH_TRIPLET)

DIST := dist

# 三个二进制:控制面 xdp-ban + 数据面 xdp-agent / xdp-sampler
.PHONY: all
all: bpf build

## bpf: 编译 eBPF 目标文件并放到各自的 embed 目录
#
# 发布前必须先跑这个:go:embed 嵌入的是这两个 .o,
# 仓库里的是 0 字节占位文件(让无 clang 的机器也能编译 Go 部分)。
# 忘了跑的话,产出的 agent/sampler 二进制内嵌空 bytecode,启动即报错。
# release 目标会强制检查这一点。
.PHONY: bpf
bpf:
	@command -v $(CLANG) >/dev/null || \
	  { echo "缺少 $(CLANG)。安装: apt-get install clang libbpf-dev"; exit 1; }
	$(CLANG) $(BPF_CFLAGS) -c bpf/xdp_filter.c   -o cmd/xdp-agent/obj/xdp_filter.o
	$(CLANG) $(BPF_CFLAGS) -c bpf/xdp_sampler.c  -o cmd/xdp-sampler/obj/xdp_sampler.o
	@echo ">> eBPF 目标文件:"
	@ls -l cmd/xdp-agent/obj/xdp_filter.o cmd/xdp-sampler/obj/xdp_sampler.o

## bpf-check: 断言待嵌入的 .o 非空(防止发布出内嵌空 bytecode 的二进制)
.PHONY: bpf-check
bpf-check:
	@for f in cmd/xdp-agent/obj/xdp_filter.o cmd/xdp-sampler/obj/xdp_sampler.o; do \
	  if [ ! -s "$$f" ]; then \
	    echo "✗ $$f 为空 —— 先执行 \`make bpf\`,否则发布的二进制无法运行"; \
	    exit 1; \
	  fi; \
	done
	@echo "✓ eBPF 目标文件非空,可以嵌入"

## build: 编译三个纯 Go 静态二进制到当前目录
.PHONY: build
build: bpf-check
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o xdp-ban     ./cmd/xdpban
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o xdp-agent   ./cmd/xdp-agent
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o xdp-sampler ./cmd/xdp-sampler

## build-nobpf: 只编译 Go 部分,跳过 eBPF 非空检查(仅用于无 clang 环境的语法检查)
.PHONY: build-nobpf
build-nobpf:
	CGO_ENABLED=0 go build ./...

## dist: 交叉编译 linux/amd64 + linux/arm64 到 dist/,并打校验和
.PHONY: dist
dist: bpf-check
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
	@cd $(DIST) && sha256sum xdp-* > SHA256SUMS
	@echo ">> dist artifacts:" && ls -lh $(DIST)

## release: 发布前完整流程 —— 编 eBPF、跑检查、交叉编译
.PHONY: release
release: bpf check dist
	@echo ">> 发布产物已就绪,eBPF bytecode 已内嵌"

## test: 全量单元测试(含竞态检测)
.PHONY: test
test:
	CGO_ENABLED=1 go test -race ./...

## bench: 运行基准测试(含内存分配统计)
.PHONY: bench
bench:
	go test -bench=. -benchmem -run='^$$' ./...

## bench-api: 控制面压测(Gin 吞吐/延迟 + pprof 采集)
.PHONY: bench-api
bench-api: build
	./scripts/api-bench.sh

## bench-xdp: 数据面真机压测(需 root:XDP 命中率、Map 延迟、perf)
.PHONY: bench-xdp
bench-xdp:
	@echo "需要 root 与真实网卡,例:"
	@echo "  sudo ./scripts/xdp-bench.sh --iface eth0 --duration 30"

## fuzz: 对信任边界的解析函数各跑 30s 模糊测试
.PHONY: fuzz
fuzz:
	go test -run='^$$' -fuzz='^FuzzParseIPv4Prefix$$' -fuzztime=30s ./cmd/xdp-agent/
	go test -run='^$$' -fuzz='^FuzzParseRate$$'       -fuzztime=30s ./internal/web/

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
