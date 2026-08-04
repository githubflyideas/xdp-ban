package web

import (
	"sort"
	"sync"
	"time"
)

// SampleStore 是采样数据的进程内缓冲。
//
// 设计取舍:采样是高频、可丢弃的观测流,写 SQLite 会把审计库拖成时序库,
// 因此只保留最近一段窗口在内存里,供仪表板即时展示。重启即丢,这是可接受的
// ——采样反映"当下正在打什么",不是需要长期留证的审计事实。
var SampleStore = newSampleBuffer(64)

type sampleBuffer struct {
	mu      sync.RWMutex
	reports []SampleReport
	limit   int
}

func newSampleBuffer(limit int) *sampleBuffer {
	return &sampleBuffer{limit: limit, reports: make([]SampleReport, 0, limit)}
}

// Put 追加一次上报,超出容量时丢弃最旧的一条。
func (b *sampleBuffer) Put(r SampleReport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reports = append(b.reports, r)
	if len(b.reports) > b.limit {
		b.reports = b.reports[len(b.reports)-b.limit:]
	}
}

// Latest 返回最近一次上报;没有数据时第二个返回值为 false。
func (b *sampleBuffer) Latest() (SampleReport, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.reports) == 0 {
		return SampleReport{}, false
	}
	return b.reports[len(b.reports)-1], true
}

// TopFlows 按包数聚合最近 window 内的流,返回前 n 条。
// 用于仪表板"当前最吵的来源"视图。
//
// 聚合在读锁下进行,复杂度 O(reports × flows)。缓冲容量固定(默认 64 份),
// 单份流数由采样器上报间隔决定,因此这是有界工作量;基准见 BenchmarkTopFlows。
// key 用定长数组而非字符串拼接,避免每条流一次堆分配。
func (b *sampleBuffer) TopFlows(window time.Duration, n int) []FlowSample {
	cutoff := time.Now().Add(-window).Unix()

	b.mu.RLock()
	defer b.mu.RUnlock()

	type flowKey struct {
		src, dst, proto string
	}
	agg := make(map[flowKey]*FlowSample, 256)
	for i := range b.reports {
		r := &b.reports[i]
		if r.Timestamp < cutoff {
			continue
		}
		for j := range r.Flows {
			f := &r.Flows[j]
			k := flowKey{f.SrcIP, f.DstIP, f.Proto}
			if cur, ok := agg[k]; ok {
				cur.PktCount += f.PktCount
				cur.ByteCount += f.ByteCount
				if f.LastSeen > cur.LastSeen {
					cur.LastSeen = f.LastSeen
				}
			} else {
				cp := *f
				agg[k] = &cp
			}
		}
	}

	out := make([]FlowSample, 0, len(agg))
	for _, f := range agg {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PktCount > out[j].PktCount })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// SamplingN 返回最近一次上报所用的采样率;无数据时返回 0。
func (b *sampleBuffer) SamplingN() int {
	if r, ok := b.Latest(); ok {
		return r.SamplingN
	}
	return 0
}
