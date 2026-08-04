package web

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// BenchmarkTopFlows 是仪表板热路径:每次打开采样页都要在读锁下
// 把整个环形缓冲重新聚合一遍。缓冲满(64 份上报 × 每份若干流)时的开销
// 直接决定采样页的响应延迟。
func BenchmarkTopFlows(b *testing.B) {
	for _, flowsPerReport := range []int{10, 100, 500} {
		b.Run(fmt.Sprintf("flows=%d", flowsPerReport), func(b *testing.B) {
			buf := newSampleBuffer(64)
			now := time.Now().Unix()
			for i := 0; i < 64; i++ {
				flows := make([]FlowSample, flowsPerReport)
				for j := range flows {
					flows[j] = FlowSample{
						SrcIP: fmt.Sprintf("203.0.113.%d", j%256),
						DstIP: "10.0.0.1", Proto: "tcp",
						PktCount: int64(j), ByteCount: int64(j * 64), LastSeen: now,
					}
				}
				buf.Put(SampleReport{Timestamp: now, Flows: flows})
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = buf.TopFlows(5*time.Minute, 20)
			}
		})
	}
}

// BenchmarkSampleBufferPut 上报写入路径:采样器每 10s 写一次,
// 但突发或多采样器时会更频繁。
func BenchmarkSampleBufferPut(b *testing.B) {
	buf := newSampleBuffer(64)
	report := SampleReport{
		Timestamp: time.Now().Unix(),
		Flows:     make([]FlowSample, 100),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Put(report)
	}
}

// TestSampleBuffer_ConcurrentReadWrite 显式制造读写并发:
// 上报 goroutine 狂写,仪表板 goroutine 狂读聚合。
// 配合 -race 才能证明 RWMutex 用对了,而不是"碰巧没崩"。
func TestSampleBuffer_ConcurrentReadWrite(t *testing.T) {
	buf := newSampleBuffer(64)
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 4 个写者
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := SampleReport{
				Timestamp: time.Now().Unix(),
				SamplingN: 100,
				Flows: []FlowSample{
					{SrcIP: fmt.Sprintf("10.0.0.%d", id), DstIP: "10.0.0.1", Proto: "tcp", PktCount: 1},
				},
			}
			for {
				select {
				case <-stop:
					return
				default:
					buf.Put(r)
				}
			}
		}(w)
	}

	// 4 个读者
	for rdr := 0; rdr < 4; rdr++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = buf.TopFlows(time.Minute, 10)
					_ = buf.SamplingN()
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	// 缓冲长度不得超过容量上限(Put 的裁剪逻辑在并发下也要成立)
	if got, _ := buf.Latest(); got.SamplingN != 100 {
		t.Errorf("并发写后 SamplingN = %d, 期望 100", got.SamplingN)
	}
}
