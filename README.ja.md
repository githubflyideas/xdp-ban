<div align="center">

# XDP-ban

**見つけて、即ブロック。**

eBPF トラフィックサンプリング + ガバナンス付き遮断 —— 単一バイナリで。

[English](README.md) · [中文](README.zh.md) · 日本語 · [한국어](README.ko.md)

</div>

---

多くのツールはトラフィックを**見る**か**遮断する**かのどちらかで、両方はできず、しかも背後に重厚なスタックを必要とします。XDP-ban はその両方を、コピーして実行するだけの単一静的バイナリで実現します。

eBPF で受信トラフィックをサンプリングし、ホストに何が来ているかを可視化し、遮断します —— 本物の承認フロー・ロール権限・監査ログを通じて。遮断は最前段(**XDP / nftables / iptables**)で実行され、しつこい攻撃者にはブロック時間が段階的に延長されます。

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
<img src="docs/img/ladder.svg" width="49%"/> <img src="docs/img/login.svg" width="49%"/>
</div>

## 特徴

- **見つけて即ブロック** —— 受信 eBPF サンプリングとワンクリック遮断。
- **ガバナンス** —— 承認フロー、ロール権限、改ざん不可の監査ログ、メール承認リンク。
- **段階的ブロック** —— 常習者はブロック時間が段階的に延長、最終的に恒久ブロック。
- **3 つのバックエンド** —— XDP/bpfilter(最速)、nftables(既定)、legacy iptables(旧カーネル)。
- **単一バイナリ** —— 純 Go、cgo なし、外部 DB 不要。コピーして実行。

## クイックスタート

```bash
CGO_ENABLED=0 go build -ldflags "-s -w" -o xdp-ban ./cmd/xdpban
./xdp-ban          # http://localhost:8080  (既定 admin / admin12345 — 必ず変更)
```

データは単一の `xdpban.db` ファイルに保存。バックアップはファイルをコピーするだけ。

## ソースからビルド

```bash
go mod tidy
CGO_ENABLED=0 go build -o xdp-ban ./cmd/xdpban
go test ./internal/...
```

## ライセンス

Apache-2.0。[LICENSE](LICENSE) を参照。
