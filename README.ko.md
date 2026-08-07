<div align="center">

# XDP-ban

**보이면, 차단한다.**

eBPF 트래픽 샘플링 + 거버넌스 기반 차단 —— 단일 바이너리로.

[English](README.md) · [中文](README.zh.md) · [日本語](README.ja.md) · 한국어

</div>

---

대부분의 도구는 트래픽을 **보거나** **차단하거나** 둘 중 하나만 하며, 게다가 뒤에 무거운 스택을 필요로 합니다. XDP-ban 은 이 둘을 모두, 복사해서 실행하기만 하면 되는 단일 정적 바이너리로 해냅니다.

eBPF 로 미러 트래픽을 샘플링하고, 호스트에 무엇이 들어오는지 보여주며, 차단합니다 —— 실제 승인 절차, 4-eyes 원칙, 역할 권한, 감사 로그를 통해서. 차단은 커널 **XDP** 계층에서 실행되며, 집요한 공격자에게는 차단 시간이 단계적으로 늘어납니다.

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
<img src="docs/img/ladder.svg" width="49%"/> <img src="docs/img/login.svg" width="49%"/>
</div>

## 특징

- **보이면 차단** —— 미러 트래픽에 대한 1/N 패킷 샘플링과 원클릭 차단.
- **거버넌스** —— 승인 절차, 4-eyes 원칙, 역할 권한, 변조 불가 감사 로그, 일회용 이메일 승인 링크.
- **단계적 차단** —— 상습 공격자는 차단 시간이 점점 길어져 최종적으로 영구 차단.
- **범위 차단** —— **국가 / AS 번호**로 출발지 범위를 선택하고 지정한 단일 호스트를 보호. 제출 전 영향 범위 미리보기와 쿼터 검증.
- **순수 XDP 실행** —— nftables 도 iptables 도 거치지 않고, 에이전트가 eBPF 맵을 직접 씁니다.
- **단일 바이너리** —— 순수 Go, `CGO_ENABLED=0`, 외부 DB 불필요. 복사 후 실행.

## 구성

두 개의 바이너리, 각각 독립 배포 가능:

| 바이너리 | 역할 | root 필요 |
|---|---|---|
| `xdp-ban` | 컨트롤 플레인 + 집행: 웹 UI, 승인, SQLite, XDP 맵 기록 | 예 |
| `xdp-sampler` | 관측: 미러 포트에서 1/N 샘플링 후 플로우 보고 | 예 |

샘플링은 **아웃오브밴드**입니다. 트래픽의 복사본을 관측하며 항상 `XDP_PASS` 를 반환합니다.

`xdp-ban` 은 이전에 컨트롤 플레인과 별도의 `xdp-agent` 집행기로 나뉘어
있었습니다(후자는 컨트롤 플레인 자신의 HTTP API 를 폴링해 지시를 받아옴).
두 프로세스는 통합되었고, `xdp-ban` 이 직접 XDP 차단 프로그램을 로드·
어태치하고 승인된 차단을 데이터베이스에 직접 실행합니다(로컬 HTTP
왕복 없음). 어느 인터페이스에 붙일지는 `-iface <ifname>`(업무용 NIC,
미러 포트가 아님)으로 지정합니다.

## 빠른 시작

```bash
make bpf     # eBPF 오브젝트 컴파일(clang 필요)
make build   # xdp-ban + xdp-sampler 빌드

sudo ./xdp-ban -iface eth0    # http://localhost:8080  (기본 admin / admin12345 — 반드시 변경)
```

데이터는 단일 `xdpban.db` 파일에 저장. 백업은 파일 복사면 끝.

데이터 플레인(root, 실제로 처리하는 호스트에서):

```bash
sudo ./xdp-sampler -d eth1 -url http://<control>:8080/api/v1/samples -n 100 -key <API_KEY>
```

## 범위 차단(국가 / AS)

"AS4134 에서 10.0.1.100 으로 향하는 모든 트래픽 차단"에는 IP 프리픽스 DB 가 필요합니다. IPv4 테이블은 약 120 만 항목이므로 **바이너리에 포함하지 않습니다**.

```bash
curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz
XDPBAN_PREFIX_DB=./ip2asn-v4.tsv.gz ./xdp-ban
```

두 가지 제약은 의도적이며 백엔드에서 강제됩니다:

- **대상은 단일 호스트(`/32`)만.** 커널은 `LPM_TRIE` 로 *출발지* 최장 일치를 수행합니다. 대상에도 프리픽스를 허용하면 2차원 최장 일치가 필요해지고, `LPM_TRIE` 로는 표현할 수 없습니다.
- **제출 전 영향 범위 미리보기와 쿼터 검증 필수.** 한 국가가 수만 프리픽스로 확장될 수 있습니다. UI 가 정확한 테이블 항목 소비량과 IPv4 공간 점유율을 보여주고, 과도한 선택은 거부하며 비정상적으로 넓은 범위는 명시적 확인을 요구합니다(확인은 감사 로그에 기록).

## 소스에서 빌드

```bash
make bpf      # clang → cmd/{xdpban,xdp-sampler}/obj/*.o, go:embed 로 임베드
make build    # xdp-ban + xdp-sampler
make check    # go vet + go test -race
make dist     # linux/{amd64,arm64} 크로스 컴파일 + SHA256SUMS
```

엔지니어링 노트(동시성 모델, 에러 처리 규약, Go/eBPF 경계, 실측 프로파일링 결과)는 [ENGINEERING.md](ENGINEERING.md) 참조.

## 현황

컨트롤 플레인과 두 데이터 플레인 모두 빌드되고 `go vet` 및 `go test -race` 를 통과하며, HTTP 를 통한 엔드투엔드 검증을 마쳤습니다. XDP 처리량과 패킷당 비용은 실제 하드웨어에서 **측정하지 않았습니다** —— 벤치마크 스크립트는 제공하지만 수치는 주장하지 않습니다.

## 라이선스

Apache-2.0. [LICENSE](LICENSE) 참조.
