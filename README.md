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

Two binaries, each independently deployable:

| Binary | Role | Needs root |
|---|---|---|
| `xdp-ban` | Control plane + enforcement: web UI, approvals, SQLite, writes XDP ban maps | yes |
| `xdp-sampler` | Observation: 1/N sampling on the mirror port, reports flows | yes |

```
switch mirror ──▶ [eth1] xdp_sampler.o ──ringbuf──▶ xdp-sampler ──HTTP──▶ xdp-ban
                                                                            │
production ─────▶ [eth0] xdp_filter.o ◀──eBPF map────────────────── (in-process)
```

`xdp-ban` used to be split into a control plane and a separate `xdp-agent`
executor that polled the control plane's own HTTP API for orders. They've
been merged: `xdp-ban` now loads and attaches the XDP filter program itself
and executes approved bans directly against the database, no local HTTP
round-trip. Pass `-iface <ifname>` (the production NIC, not the mirror port)
so it knows where to attach.

Sampling stays a separate binary — it runs on the mirror port, only observes
(`XDP_PASS`, never drops), and has no state in common with enforcement.

## Quick start

Download the binary and run it. No dependencies, no build step — the eBPF objects are already inside.

```bash
# x86_64
curl -L -o xdp-ban https://github.com/githubflyideas/xdp-ban/releases/download/v0.28/xdp-ban-linux-amd64
# arm64: replace amd64 with arm64 in the URL above

chmod +x xdp-ban
sudo ./xdp-ban -iface eth0    # http://localhost:8080 — root needed to attach XDP
```

### Default accounts

Four accounts are seeded on first run, one per role. **Change these passwords
immediately** — they are printed in this README and therefore public.

| Username | Password | Role | Can do |
|---|---|---|---|
| `admin` | `admin12345` | admin | everything, incl. user management and system config |
| `approver` | `approver12345` | approver | approve / reject / revoke bans, view audit |
| `operator` | `operator12345` | operator | submit ban requests, view audit |
| `viewer` | `viewer12345` | viewer | read-only |

Why four and not one: the **four-eyes principle** requires the submitter and the
approver to be different people. A single account cannot approve its own request,
so you need at least two usable logins to complete a ban.

Change passwords under **用户管理 / Users** (admin only). You can also add, disable
and delete users there — every change is written to the audit log.

Data lives in a single `xdpban.db` file. Back up = copy the file.

Data plane sampler (root, on the host doing the observing):

```bash
curl -L -o xdp-sampler https://github.com/githubflyideas/xdp-ban/releases/download/v0.28/xdp-sampler-linux-amd64
chmod +x xdp-sampler

sudo ./xdp-sampler -d eth1 -url http://<control>:8080/api/v1/samples -n 4096 -key <API_KEY>
```

All releases: https://github.com/githubflyideas/xdp-ban/releases

## Traffic analysis (ElastiFlow)

The sampler can export sampled flows as **NetFlow v5** to ElastiFlow for
visualization, alongside its report to xdp-ban. Add `-netflow <collector>:2055`:

```bash
sudo ./xdp-sampler -d eth1 -url http://<control>:8080/api/v1/samples \
     -n 4096 -key <API_KEY> -netflow 127.0.0.1:2055
```

A ready-to-run stack (Elasticsearch + Kibana + ElastiFlow) lives in
[`deploy/elastiflow/`](deploy/elastiflow/) — `docker compose up -d`, then point
the sampler at `udp/2055`. The sampling rate is written into every packet so
ElastiFlow restores true traffic volume automatically. See
[deploy/elastiflow/README.md](deploy/elastiflow/README.md) for why NetFlow v5
and not IPFIX.

## Scoped bans (country / ASN)

```bash
curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz
XDPBAN_PREFIX_DB=./ip2asn-v4.tsv.gz ./xdp-ban
```

Without it, everything else works and the UI tells you the feature is unavailable.

## Configuration

`xdp-ban` flags:

| Flag | Default | Purpose |
|---|---|---|
| `-iface` | — (required) | Production NIC to attach the XDP ban program to. No default — silently skipping this would mean bans stay in the approval log without ever blocking traffic. |
| `-poll-interval` | `5s` | How often to scan for newly-approved dispatches to execute |

`xdp-ban` environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `XDPBAN_DB` | `xdpban.db` | SQLite file path |
| `XDPBAN_ADDR` | `:8080` | Listen address |
| `XDPBAN_API_KEY` | `changeme` | Shared key for the sampler's report API |
| `XDPBAN_BASE_URL` | `http://localhost:8080` | Prefix for email approval links |
| `XDPBAN_IFACE` | — | Alternative to `-iface` |
| `XDPBAN_PREFIX_DB` | — | Path to `ip2asn-v4.tsv[.gz]`; enables scoped bans |
| `XDPBAN_COOKIE_SECURE` | — | Set to any value when behind TLS |
| `XDPBAN_PPROF` | — | Set to any value to expose `/debug/pprof` (bind to a private interface only) |

`xdp-sampler` flags (exactly five, fixed at startup — sampling rate is not
adjustable at runtime; restart the process to change it):

| Flag | Default | Purpose |
|---|---|---|
| `-d` | `eth1` | Mirror interface to sample from |
| `-n` | `100` | Sampling rate (1/N) |
| `-url` | `http://localhost:8080/api/v1/samples` | `xdp-ban` report endpoint |
| `-key` | `changeme` | API key for reporting to `xdp-ban` |
| `-netflow` | — | NetFlow v5 collector address (`host:port`); empty disables export |

## Build from source

Only needed if you're hacking on it — released binaries already bundle the eBPF objects.
Requires `clang` and `libbpf-dev`.

```bash
make bpf      # clang → cmd/{xdpban,xdp-sampler}/obj/*.o (embedded via go:embed)
make build    # xdp-ban + xdp-sampler; refuses to run if the .o files are missing
make check    # go vet + go test -race
make release  # bpf + check + cross-compile linux/{amd64,arm64}
```

The `.o` files are build artifacts, not tracked in git. `make build` asserts they
are non-empty, so a binary with empty bytecode can't be shipped by accident.

Engineering notes — concurrency model, error-handling conventions, Go/eBPF boundary, and measured profiling results — are in [ENGINEERING.md](ENGINEERING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
