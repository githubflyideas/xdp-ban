#!/usr/bin/env bash
# xdp-bench.sh —— 数据面真机压测:XDP 命中率、每包开销、Map 操作延迟
#
# 为什么需要真机:XDP 运行在网卡驱动层,Go 的 pprof 看不到内核侧开销;
# eBPF map 的实际查表成本、DROP 路径的每包 CPU,只能在挂载了程序的
# 真实网卡上用 bpftool / perf 观测。
#
# 用法:
#   sudo ./scripts/xdp-bench.sh --iface eth0 --duration 30
#   sudo ./scripts/xdp-bench.sh --iface eth0 --map-only     # 只测 map 操作
#
# 前置:make bpf && make build,且 xdp-agent 已挂载程序到 --iface
set -euo pipefail

IFACE=""
DURATION=30
MAP_ONLY=0
OUT_DIR="dist/bench-$(date +%Y%m%d-%H%M%S)"

usage() {
    sed -n '2,14p' "$0" | sed 's/^# \?//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)    IFACE="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --map-only) MAP_ONLY=1; shift ;;
        --out)      OUT_DIR="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *) echo "未知参数: $1" >&2; usage 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "需要 root(读 eBPF map、perf 采样)" >&2; exit 1; }
[[ -n "$IFACE" || $MAP_ONLY -eq 1 ]] || { echo "必须指定 --iface" >&2; usage 1; }

mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/report.txt"

log()  { echo "$@" | tee -a "$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }

log "==============================================="
log " xdp-ban 数据面压测  $(date -Is)"
log "==============================================="
log "内核:   $(uname -r)"
log "网卡:   ${IFACE:-<skip>}"
log "时长:   ${DURATION}s"
log ""

# ---------- 0. 环境自检 ----------
log "--- 环境自检 ---"
for tool in bpftool ip; do
    if have "$tool"; then log "  ✓ $tool"; else log "  ✗ $tool 缺失(部分测量将跳过)"; fi
done
for tool in perf tcpreplay pktgen-dpdk; do
    have "$tool" && log "  ✓ $tool(可选)" || log "  - $tool 未装(对应测量跳过)"
done
log ""

# ---------- 1. XDP 程序挂载状态 ----------
if [[ -n "$IFACE" ]]; then
    log "--- XDP 挂载状态 ---"
    ip -d link show dev "$IFACE" 2>&1 | grep -iE "xdp|prog" | tee -a "$LOG" || log "  (未检测到 XDP 程序)"
    log ""
fi

# ---------- 2. eBPF Map 概况 ----------
if have bpftool; then
    log "--- eBPF Map 概况 ---"
    bpftool map show 2>/dev/null | grep -iE "ban_list|sampling_rate|counters|flow_table|samples" \
        | tee -a "$LOG" || log "  (未找到 xdp-ban 的 map,程序可能未加载)"
    log ""

    log "--- Map 内存占用 ---"
    bpftool map show -j 2>/dev/null \
      | python3 -c '
import json,sys
try: maps=json.load(sys.stdin)
except Exception: sys.exit(0)
want={"ban_list","sampling_rate","counters","flow_table","samples"}
for m in maps:
    if m.get("name") in want:
        ks,vs,me=m.get("key_size",0),m.get("value_size",0),m.get("max_entries",0)
        print(f"  {m[\"name\"]:<16} 条目上限={me:<8} 单条={ks}+{vs}B  预留≈{(ks+vs)*me/1024:.1f}KB")
' | tee -a "$LOG"
    log ""
fi

# ---------- 3. Map 操作延迟(用户态视角) ----------
log "--- Map 操作延迟(bpftool 单次往返) ---"
if have bpftool && bpftool map show 2>/dev/null | grep -q ban_list; then
    MAPID=$(bpftool map show 2>/dev/null | awk '/ban_list/{gsub(":","",$1); print $1; exit}')
    log "  ban_list map id = $MAPID"

    # 200 次 lookup 取平均。bpftool 每次都要 open/close fd,
    # 因此这是"上界":agent 常驻进程复用 fd,实际远快于此。
    N=200
    START=$(date +%s%N)
    for _ in $(seq $N); do
        bpftool map lookup id "$MAPID" key 0xcb 0x00 0x71 0x07 0x00 0x00 0x00 0x00 >/dev/null 2>&1 || true
    done
    END=$(date +%s%N)
    log "  lookup ×$N 平均: $(( (END-START)/N/1000 )) µs/次(含 bpftool 进程开销,属上界)"

    START=$(date +%s%N)
    for i in $(seq $N); do
        bpftool map update id "$MAPID" \
            key 0x0a 0x00 $(printf '0x%02x' $((i/256))) $(printf '0x%02x' $((i%256))) 0x00 0x00 0x00 0x00 \
            value 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 \
            >/dev/null 2>&1 || true
    done
    END=$(date +%s%N)
    log "  update ×$N 平均: $(( (END-START)/N/1000 )) µs/次"
else
    log "  跳过(ban_list map 不存在)"
fi
log ""

[[ $MAP_ONLY -eq 1 ]] && { log "--map-only 指定,结束。报告: $LOG"; exit 0; }

# ---------- 4. 基线快照 ----------
snapshot_counters() {
    if have bpftool && bpftool map show 2>/dev/null | grep -q counters; then
        local id
        id=$(bpftool map show 2>/dev/null | awk '/counters/{gsub(":","",$1); print $1; exit}')
        bpftool map dump id "$id" 2>/dev/null || true
    fi
}
iface_stats() { ip -s -j link show dev "$IFACE" 2>/dev/null || ip -s link show dev "$IFACE"; }

log "--- 采集基线 ---"
snapshot_counters > "$OUT_DIR/counters.before.txt"
iface_stats       > "$OUT_DIR/iface.before.txt"
cat /proc/stat | head -1 > "$OUT_DIR/cpu.before.txt"
log "  已保存基线快照"
log ""

# ---------- 5. 内核侧 CPU 剖析 ----------
if have perf; then
    log "--- perf: XDP 路径 CPU 剖析(${DURATION}s) ---"
    log "  采样中…(请同时施加流量负载)"
    perf record -F 99 -a -g --output="$OUT_DIR/perf.data" -- sleep "$DURATION" 2>/dev/null || \
        log "  perf record 失败(可能缺少 perf_event_paranoid 权限)"

    if [[ -f "$OUT_DIR/perf.data" ]]; then
        perf report --stdio --input="$OUT_DIR/perf.data" --sort=symbol 2>/dev/null \
            | head -40 > "$OUT_DIR/perf.report.txt" || true
        log "  Top 内核符号(关注 xdp / bpf_prog / bpf_map 相关):"
        grep -iE "bpf|xdp" "$OUT_DIR/perf.report.txt" 2>/dev/null | head -12 | tee -a "$LOG" || \
            log "    (未捕获到 bpf/xdp 符号,可能无流量或程序未挂载)"
    fi
    log ""
else
    log "--- perf 未安装,跳过内核 CPU 剖析 ---"
    log "    安装: apt-get install linux-tools-\$(uname -r)"
    log ""
    sleep "$DURATION"
fi

# ---------- 6. 结果快照与命中率 ----------
log "--- 采集结果 ---"
snapshot_counters > "$OUT_DIR/counters.after.txt"
iface_stats       > "$OUT_DIR/iface.after.txt"

log ""
log "--- XDP 命中率 ---"
if [[ -s "$OUT_DIR/counters.before.txt" && -s "$OUT_DIR/counters.after.txt" ]]; then
    log "  counters map(索引 0=dropped, 1=passed):"
    log "  [before]"; sed 's/^/    /' "$OUT_DIR/counters.before.txt" | tee -a "$LOG"
    log "  [after ]"; sed 's/^/    /' "$OUT_DIR/counters.after.txt"  | tee -a "$LOG"
    log ""
    log "  命中率 = dropped / (dropped + passed);差值取 after - before"
else
    log "  无 counters 数据(程序未挂载或 map 名不符)"
fi
log ""

log "--- 网卡收包统计(每包开销参考) ---"
log "  用 after - before 的 RX packets 除以 ${DURATION}s 得 pps;"
log "  结合 perf 中 bpf_prog_run 的 cum% 可估算每包 CPU 占比。"
log ""

# ---------- 7. 流量回放(可选) ----------
if have tcpreplay; then
    log "--- 流量回放提示 ---"
    log "  验证 1/N 采样准确性:"
    log "    sudo tcpreplay -i <采样网卡> -t -K sample.pcap"
    log "  然后核对 xdp-ban /sampling 页面上报的包数 ≈ 实际包数 / N"
    log ""
fi

log "==============================================="
log " 完成。产物目录: $OUT_DIR"
log "==============================================="
ls -la "$OUT_DIR" | tee -a "$LOG"
