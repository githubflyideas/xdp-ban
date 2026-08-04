<div align="center">

# XDP-ban

**보이면, 차단한다.**

eBPF 트래픽 샘플링 + 거버넌스 기반 차단 —— 단일 바이너리로.

[English](README.md) · [中文](README.zh.md) · [日本語](README.ja.md) · 한국어

</div>

---

대부분의 도구는 트래픽을 **보거나** **차단하거나** 둘 중 하나만 하며, 게다가 뒤에 무거운 스택을 필요로 합니다. XDP-ban 은 이 둘을 모두, 복사해서 실행하기만 하면 되는 단일 정적 바이너리로 해냅니다.

eBPF 로 인바운드 트래픽을 샘플링하고, 호스트에 무엇이 들어오는지 보여주며, 차단합니다 —— 실제 승인 절차, 역할 권한, 감사 로그를 통해서. 차단은 가장 앞단(**XDP / nftables / iptables**)에서 실행되며, 집요한 공격자에게는 차단 시간이 단계적으로 늘어납니다.

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
<img src="docs/img/ladder.svg" width="49%"/> <img src="docs/img/login.svg" width="49%"/>
</div>

## 특징

- **보이면 차단** —— 인바운드 eBPF 샘플링과 원클릭 차단.
- **거버넌스** —— 승인 절차, 역할 권한, 변조 불가 감사 로그, 이메일 승인 링크.
- **단계적 차단** —— 상습 공격자는 차단 시간이 점점 길어져 최종적으로 영구 차단.
- **세 가지 백엔드** —— XDP/bpfilter(최속), nftables(기본), legacy iptables(구형 커널).
- **단일 바이너리** —— 순수 Go, cgo 없음, 외부 DB 불필요. 복사 후 실행.

## 빠른 시작

```bash
CGO_ENABLED=0 go build -ldflags "-s -w" -o xdp-ban ./cmd/xdpban
./xdp-ban          # http://localhost:8080  (기본 admin / admin12345 — 반드시 변경)
```

데이터는 단일 `xdpban.db` 파일에 저장. 백업은 파일 복사면 끝.

## 소스에서 빌드

```bash
go mod tidy
CGO_ENABLED=0 go build -o xdp-ban ./cmd/xdpban
go test ./internal/...
```

## 라이선스

Apache-2.0. [LICENSE](LICENSE) 참조.
