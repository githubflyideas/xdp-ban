#!/usr/bin/env bash
# api-bench.sh —— 控制面压测:Gin API 吞吐/延迟 + Go pprof 采集
#
# 覆盖第 2 问中"Go 业务处理到 Gin API 返回"这一段:
# 用真实 HTTP 负载打各条路由,同时抓 CPU/heap/block/mutex profile,
# 定位是 SQLite 争锁、模板渲染,还是采样聚合成为瓶颈。
#
# 用法:
#   ./scripts/api-bench.sh                          # 自启服务并压测
#   ./scripts/api-bench.sh --url http://host:8080   # 压测已运行的实例
set -euo pipefail

URL=""
DURATION=10
CONCURRENCY=50
OUT_DIR="dist/api-bench-$(date +%Y%m%d-%H%M%S)"
API_KEY="${XDPBAN_API_KEY:-changeme}"
OWN_SERVER=0
PORT=18099

usage() { sed -n '2,12p' "$0" | sed 's/^# \?//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)         URL="$2"; shift 2 ;;
        --duration)    DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --out)         OUT_DIR="$2"; shift 2 ;;
        -h|--help)     usage ;;
        *) echo "未知参数: $1" >&2; usage 1 ;;
    esac
done

mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/report.txt"
log()  { echo "$@" | tee -a "$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }

log "==============================================="
log " xdp-ban 控制面压测  $(date -Is)"
log "==============================================="

# ---------- 启动服务(若未指定外部实例) ----------
if [[ -z "$URL" ]]; then
    [[ -x ./xdp-ban ]] || { echo "未找到 ./xdp-ban,请先 make build" >&2; exit 1; }
    URL="http://127.0.0.1:$PORT"
    DB="$OUT_DIR/bench.db"
    log "启动本地实例: $URL (db=$DB)"
    XDPBAN_DB="$DB" XDPBAN_ADDR=":$PORT" GIN_MODE=release \
        XDPBAN_PPROF=1 XDPBAN_API_KEY="$API_KEY" \
        ./xdp-ban > "$OUT_DIR/server.log" 2>&1 &
    SRV_PID=$!
    OWN_SERVER=1
    trap 'kill $SRV_PID 2>/dev/null || true' EXIT
    for _ in $(seq 20); do
        curl -sf -o /dev/null "$URL/login" && break
        sleep 0.3
    done
fi

log "目标: $URL   并发: $CONCURRENCY   时长: ${DURATION}s"
log ""

# ---------- 登录取会话 ----------
COOKIE="$OUT_DIR/cookies.txt"
curl -s -c "$COOKIE" -o /dev/null -X POST \
     -d "username=admin&password=admin12345" "$URL/login" || true
if grep -q sid "$COOKIE" 2>/dev/null; then
    log "✓ 已登录(会话 cookie 就绪)"
else
    log "✗ 登录失败,受保护路由的压测将被跳过"
fi
log ""

# ---------- 压测器选择 ----------
BENCH_TOOL=""
for t in hey oha wrk ab; do have "$t" && { BENCH_TOOL="$t"; break; }; done
if [[ -z "$BENCH_TOOL" ]]; then
    log "未找到压测工具(hey/oha/wrk/ab 任一),退化为 curl 串行测量"
    log "  建议: go install github.com/rakyll/hey@latest"
fi
log "压测工具: ${BENCH_TOOL:-curl(串行)}"
log ""

bench_one() {
    local name="$1" path="$2" extra="${3:-}"
    log "--- $name  ($path) ---"
    case "$BENCH_TOOL" in
        hey)  hey  -z "${DURATION}s" -c "$CONCURRENCY" $extra "$URL$path" 2>&1 \
                | grep -E "Requests/sec|Average|Slowest|Fastest|50%|95%|99%|Status code" | sed 's/^/  /' | tee -a "$LOG" ;;
        oha)  oha  -z "${DURATION}s" -c "$CONCURRENCY" --no-tui $extra "$URL$path" 2>&1 \
                | grep -E "Requests/sec|Average|Slowest|95|99" | sed 's/^/  /' | tee -a "$LOG" ;;
        wrk)  wrk -d"${DURATION}s" -c"$CONCURRENCY" -t4 --latency "$URL$path" 2>&1 \
                | grep -E "Requests/sec|Latency|50%|95%|99%" | sed 's/^/  /' | tee -a "$LOG" ;;
        ab)   ab -t "$DURATION" -c "$CONCURRENCY" $extra "$URL$path" 2>&1 \
                | grep -E "Requests per second|Time per request|50%|95%|99%" | sed 's/^/  /' | tee -a "$LOG" ;;
        *)    local n=200 start end
              start=$(date +%s%N)
              for _ in $(seq $n); do curl -s -o /dev/null -b "$COOKIE" $extra "$URL$path"; done
              end=$(date +%s%N)
              log "  $n 次串行平均: $(( (end-start)/n/1000000 )) ms/请求" ;;
    esac
    log ""
}

# ---------- 各路由压测 ----------
bench_one "登录页(无 DB 查询,模板渲染基线)" "/login"
bench_one "API 鉴权拒绝路径(401 快路径)"    "/api/v1/dispatch/pending"
bench_one "API 指令轮询(agent 热路径)"      "/api/v1/dispatch/pending" "-H X-API-Key:$API_KEY"

if grep -q sid "$COOKIE" 2>/dev/null; then
    SID=$(awk '/sid/{print $7}' "$COOKIE" | tail -1)
    bench_one "仪表板(3 次 SQLite count + 模板)" "/dashboard" "-H Cookie:sid=$SID"
    bench_one "采样页(内存聚合 TopFlows + 模板)" "/sampling"  "-H Cookie:sid=$SID"
    bench_one "封禁列表(单表 200 行查询)"        "/bans"      "-H Cookie:sid=$SID"
fi

# ---------- 采样上报写入压测 ----------
log "--- 采样上报写入(sampler → xdp-ban 热路径) ---"
PAYLOAD="$OUT_DIR/sample.json"
python3 - "$PAYLOAD" <<'PY'
import json,sys,time
flows=[{"src_ip":f"203.0.113.{i%256}","dst_ip":"10.0.0.1","src_port":1024+i,
        "dst_port":443,"proto":"tcp","pkt_count":i,"byte_count":i*64,
        "last_seen_unix":int(time.time())} for i in range(200)]
json.dump({"timestamp":int(time.time()),"device":"eth1","sampling_n":100,
           "flows":flows,"global_stat":{}}, open(sys.argv[1],"w"))
PY
if [[ "$BENCH_TOOL" == "hey" ]]; then
    hey -z "${DURATION}s" -c 10 -m POST -T application/json \
        -H "X-API-Key:$API_KEY" -D "$PAYLOAD" "$URL/api/v1/samples" 2>&1 \
        | grep -E "Requests/sec|Average|95%|Status code" | sed 's/^/  /' | tee -a "$LOG"
else
    n=100; start=$(date +%s%N)
    for _ in $(seq $n); do
        curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
             -H "X-API-Key: $API_KEY" --data-binary "@$PAYLOAD" "$URL/api/v1/samples"
    done
    end=$(date +%s%N)
    log "  $n 次(每次 200 条流)平均: $(( (end-start)/n/1000000 )) ms"
fi
log ""

# ---------- pprof 采集(必须与负载并行) ----------
# 关键:CPU profile 只在采样窗口内有负载才有意义。
# 先后串行采集会得到全零的 profile —— 这是很容易踩的坑。
if curl -sf -o /dev/null "$URL/debug/pprof/" 2>/dev/null; then
    log "--- 采集 pprof(与负载并行) ---"

    # 后台施加持续负载
    LOAD_PID=""
    if [[ -n "$BENCH_TOOL" && "$BENCH_TOOL" == "hey" ]]; then
        hey -z 8s -c "$CONCURRENCY" -H "X-API-Key:$API_KEY" \
            "$URL/api/v1/dispatch/pending" >/dev/null 2>&1 &
        LOAD_PID=$!
    else
        # 无压测工具时用并行 curl 循环压 8 秒
        (
          end=$(( $(date +%s) + 8 ))
          while [[ $(date +%s) -lt $end ]]; do
            for _ in $(seq 8); do
              curl -s -o /dev/null -b "$COOKIE" "$URL/dashboard" &
              curl -s -o /dev/null -H "X-API-Key: $API_KEY" "$URL/api/v1/dispatch/pending" &
            done
            wait
          done
        ) >/dev/null 2>&1 &
        LOAD_PID=$!
    fi

    sleep 1  # 让负载先跑起来

    # CPU profile 在负载中采 5 秒
    curl -sf -o "$OUT_DIR/cpu.pprof" "$URL/debug/pprof/profile?seconds=5" \
        && log "  ✓ cpu.pprof(负载中采集)" || log "  - cpu 采集失败"

    # 其余为瞬时快照,趁负载还在时抓
    for name in heap block mutex goroutine allocs; do
        if curl -sf -o "$OUT_DIR/$name.pprof" "$URL/debug/pprof/$name"; then
            log "  ✓ $name.pprof"
        else
            log "  - $name 采集失败"
        fi
    done

    [[ -n "$LOAD_PID" ]] && { kill "$LOAD_PID" 2>/dev/null || true; wait "$LOAD_PID" 2>/dev/null || true; }
    log ""

    if have go && [[ -s "$OUT_DIR/cpu.pprof" ]]; then
        log "--- CPU Top 10 ---"
        go tool pprof -top -nodecount=10 "$OUT_DIR/cpu.pprof" 2>/dev/null \
            | tail -12 | sed 's/^/  /' | tee -a "$LOG" || true
        log ""
        log "--- Mutex 争用 Top 5(SQLite/会话锁是否成为瓶颈) ---"
        go tool pprof -top -nodecount=5 "$OUT_DIR/mutex.pprof" 2>/dev/null \
            | tail -7 | sed 's/^/  /' | tee -a "$LOG" || log "  (无争用数据)"
        log ""
        log "--- Block(阻塞) Top 5 ---"
        go tool pprof -top -nodecount=5 "$OUT_DIR/block.pprof" 2>/dev/null \
            | tail -7 | sed 's/^/  /' | tee -a "$LOG" || log "  (无阻塞数据)"
        log ""
        log "  注:selectgo 占比高属正常(HTTP handler 等待),"
        log "      真正要盯的是 sqlite / sync.(*RWMutex) 相关条目。"
    fi
else
    log "--- pprof 端点不可用,跳过 ---"
    log "    以 XDPBAN_PPROF=1 启动服务后可采集"
fi

log ""
log "==============================================="
log " 完成。产物目录: $OUT_DIR"
log " 交互式分析: go tool pprof -http=: $OUT_DIR/cpu.pprof"
log "==============================================="
