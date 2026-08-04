<div align="center">

# XDP-ban

**See it. Ban it.**

eBPF traffic sampling + governed banning — in a single binary.

English · [中文](README.zh.md) · [日本語](README.ja.md) · [한국어](README.ko.md)

</div>

---

Most tools can watch traffic **or** block it — never both, and never without a heavy stack behind them. XDP-ban does both, in static binaries you can copy and run.

It samples mirrored traffic with eBPF, surfaces what's hitting your hosts, and lets you ban it — through real approvals, roles, and an audit trail. Bans execute in **XDP**, at the earliest point in the kernel, with escalating durations for attackers who keep knocking.

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
<img src="docs/img/ladder.svg" width="49%"/> <img src="docs/img/login.svg" width="49%"/>
</div>

## Features

- **See it, ban it** — 1/N packet sampling on mirrored traffic, then one-click banning.
- **Governed** — approvals, four-eyes principle, role-based access, immutable audit log, one-time email approval links.
- **Escalating bans** — repeat offenders get progressively longer bans, up to permanent.
- **Scoped bans** — pick source ranges by **country / ASN**, protect a single target host. Impact is previewed and quota-checked before submission.
- **Pure XDP enforcement** — no nftables, no iptables. The agent writes eBPF maps directly.
- **Single binaries** — pure Go, `CGO_ENABLED=0`, no external DB. Copy and run.

## Architecture

Three binaries, each independently deployable:

| Binary | Role | Needs root |
|---|---|---|
| `xdp-ban` | Control plane: web UI, approvals, SQLite | no |
| `xdp-agent` | Enforcement: polls for orders, writes XDP ban maps | yes |
| `xdp-sampler` | Observation: 1/N sampling on the mirror port, reports flows | yes |

```
switch mirror ──▶ [eth1] xdp_sampler.o ──ringbuf──▶ xdp-sampler ──HTTP──▶ xdp-ban
                                                                            │
production ─────▶ [eth0] xdp_filter.o ◀──eBPF map── xdp-agent ◀──HTTP───────┘
```

Sampling is **out-of-band**: it observes a copy of the traffic and always returns `XDP_PASS`. Enforcement is a separate program on the production NIC.

## Quick start

```bash
make bpf     # compile eBPF objects (needs clang)
make build   # build the three binaries

./xdp-ban    # http://localhost:8080  (default admin / admin12345 — change it)
```

Data lives in a single `xdpban.db` file. Back up = copy the file.

Data plane (root, on the hosts doing the work):

```bash
sudo ./xdp-sampler -d eth1 -url http://<control>:8080/api/v1/samples -n 100 -key <API_KEY>
sudo ./xdp-agent   -server http://<control>:8080 -key <API_KEY>
```

## Scoped bans (country / ASN)

To ban "everything from AS4134 hitting 10.0.1.100", you need a prefix database. It is **not bundled** — the IPv4 table is ~1.2M ranges and would make "copy one file and run" a lie.

```bash
curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz
XDPBAN_PREFIX_DB=./ip2asn-v4.tsv.gz ./xdp-ban
```

Without it, everything else works and the UI tells you the feature is unavailable.

Two constraints are deliberate and enforced:

- **The target must be a single host (`/32`).** The kernel does longest-prefix matching on the *source* via `LPM_TRIE`. Allowing prefixes on the target too would require two-dimensional LPM, which `LPM_TRIE` cannot express — the fallback is a per-packet scan, unacceptable in XDP.
- **Impact is previewed and quota-checked before submission.** A country can expand to tens of thousands of prefixes. The UI shows the exact table-entry cost and the share of IPv4 space covered; oversized selections are rejected, and unusually broad ones require an explicit acknowledgement that is written to the audit log.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `XDPBAN_DB` | `xdpban.db` | SQLite file path |
| `XDPBAN_ADDR` | `:8080` | Listen address |
| `XDPBAN_API_KEY` | `changeme` | Shared key for agent/sampler API |
| `XDPBAN_BASE_URL` | `http://localhost:8080` | Prefix for email approval links |
| `XDPBAN_SAMPLER_URL` | `http://localhost:9090` | Sampler control endpoint |
| `XDPBAN_PREFIX_DB` | — | Path to `ip2asn-v4.tsv[.gz]`; enables scoped bans |
| `XDPBAN_COOKIE_SECURE` | — | Set to any value when behind TLS |
| `XDPBAN_PPROF` | — | Set to any value to expose `/debug/pprof` (bind to a private interface only) |

## Build from source

```bash
make bpf      # clang → cmd/*/obj/*.o, embedded via go:embed
make build    # three static binaries
make check    # go vet + go test -race
make dist     # cross-compile linux/{amd64,arm64} + SHA256SUMS
```

Testing and profiling:

```bash
make test       # go test -race ./...
make bench      # benchmarks with allocation stats
make fuzz       # fuzz the parsers on trust boundaries
make prof       # CPU/heap profile of the sampling hot path
make bench-api  # HTTP load + pprof against a live instance
```

For data-plane measurements on real hardware, see [`scripts/xdp-bench.sh`](scripts/xdp-bench.sh) (hit rate via `bpftool`, per-packet cost via `perf`).

Engineering notes — concurrency model, error-handling conventions, Go/eBPF boundary, and measured profiling results — are in [ENGINEERING.md](ENGINEERING.md).

## Status

The control plane and both data-plane agents build, pass `go vet` and `go test -race`, and have been exercised end to end over HTTP. XDP throughput and per-packet cost have **not** been measured on real hardware — the benchmark script is provided, the numbers are not claimed.

## License

Apache-2.0. See [LICENSE](LICENSE).
