<div align="center">

# XDP-ban

**See it. Ban it.**

eBPF traffic sampling + governed banning — in a single binary.

English · [中文](README.zh.md) · [日本語](README.ja.md) · [한국어](README.ko.md)

</div>

---

Most tools can watch traffic **or** block it — never both, and never without a heavy stack behind them. XDP-ban does both, in one static binary you can copy and run.

It samples inbound traffic with eBPF, surfaces what's hitting your host, and lets you ban it — through real approvals, roles, and an audit trail. Bans execute at the earliest possible point via **XDP / nftables / iptables**, with escalating ban durations for attackers who keep knocking.

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
<img src="docs/img/ladder.svg" width="49%"/> <img src="docs/img/login.svg" width="49%"/>
</div>

## Features

- **See it, ban it** — inbound eBPF sampling meets one-click banning.
- **Governed** — approvals, role-based access, immutable audit log, email approval links.
- **Escalating bans** — repeat attackers get progressively longer bans, up to permanent.
- **Three backends** — XDP/bpfilter (fastest), nftables (default), legacy iptables (old kernels).
- **Single binary** — pure-Go, no cgo, no external DB. Copy and run.

## Quick start

```bash
CGO_ENABLED=0 go build -ldflags "-s -w" -o xdp-ban ./cmd/xdpban
./xdp-ban          # http://localhost:8080  (default admin / admin12345 — change it)
```

Data lives in a single `xdpban.db` file. Back up = copy the file.

## Build from source

```bash
go mod tidy
CGO_ENABLED=0 go build -o xdp-ban ./cmd/xdpban
go test ./internal/...
```

## License

Apache-2.0. See [LICENSE](LICENSE).
