// Package prefixdb 的数据源同步。
//
// 三种导入方式,对应三种现实处境:
//
//  1. **在线同步** —— 能出网的环境,从多个上游拉取。多源是必要的:
//     单一上游宕机或改格式就会让功能失效,而且不同源的数据口径有差异
//     (iptoasn 偏 BGP 现实,RIR 偏注册归属),让用户能选比替他们决定好。
//
//  2. **上传文件** —— 内网/隔离环境的主流做法:在能出网的机器上下载,
//     再通过界面上传。这不是退路,对很多政企客户是唯一可行路径。
//
//  3. **本地覆盖文件** —— 用户手工维护的优先规则。商业 IP 库对
//     "这个网段到底属于谁"经常判错,而运维知道真相。本地规则优先级最高,
//     且不会被同步覆盖。
package prefixdb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Source 一个可选的上游数据源
type Source struct {
	ID       string
	Name     string
	URL      string
	Format   string // ip2asn_tsv | rir_delegated
	License  string
	Note     string
}

// Sources 内置的上游列表。
//
// 只收录:许可清晰、无需注册、单文件可直接解析的源。
// MaxMind GeoLite2 需要账号与许可协议点击同意,不适合内置自动拉取,
// 但用户可下载后走"上传文件"路径。
var Sources = []Source{
	{
		ID: "iptoasn", Name: "IPtoASN (推荐)",
		URL:    "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
		Format: "ip2asn_tsv", License: "PDDL 1.0 (公共领域)",
		Note:   "每小时更新,同时提供国家与 AS 归属,基于 BGP 实际公告",
	},
	{
		ID: "iptoasn_combined", Name: "IPtoASN (含 IPv6)",
		URL:    "https://iptoasn.com/data/ip2asn-combined.tsv.gz",
		Format: "ip2asn_tsv", License: "PDDL 1.0 (公共领域)",
		Note:   "同上但含 IPv6 记录;当前仅解析 IPv4 部分",
	},
	{
		ID: "apnic", Name: "APNIC 分配记录",
		URL:    "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
		Format: "rir_delegated", License: "APNIC 开放数据",
		Note:   "亚太地区权威注册数据,含国家但不含 AS;归属口径为注册而非路由",
	},
	{
		ID: "ripe", Name: "RIPE NCC 分配记录",
		URL:    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
		Format: "rir_delegated", License: "RIPE 开放数据",
		Note:   "欧洲与中东地区权威注册数据",
	},
}

// SourceByID 查找内置源
func SourceByID(id string) (Source, bool) {
	for _, s := range Sources {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

// SyncStatus 同步状态,供界面展示
type SyncStatus struct {
	InProgress  bool
	SourceID    string
	StartedAt   time.Time
	FinishedAt  time.Time
	BytesRead   int64
	Entries     int
	Err         string
}

var (
	syncMu     sync.RWMutex
	syncStatus SyncStatus
)

// Status 当前同步状态
func Status() SyncStatus {
	syncMu.RLock()
	defer syncMu.RUnlock()
	return syncStatus
}

// DataDir 存放前缀库与本地覆盖文件的目录
func DataDir() string {
	if d := os.Getenv("XDPBAN_DATA_DIR"); d != "" {
		return d
	}
	return "./data"
}

// ActivePath 当前生效的前缀库文件路径
func ActivePath() string { return filepath.Join(DataDir(), "prefixdb.tsv") }

// OverridePath 本地优先规则文件路径
func OverridePath() string { return filepath.Join(DataDir(), "overrides.tsv") }

// SyncFrom 从上游下载并落盘,成功后重新加载。
//
// 下载到临时文件再原子改名:直接写目标文件的话,下载中途失败会留下
// 半个文件,而重启时会把它当成有效数据加载 —— 半个前缀库比没有更糟,
// 因为封禁范围会静默变窄。
func SyncFrom(src Source) error {
	syncMu.Lock()
	if syncStatus.InProgress {
		syncMu.Unlock()
		return fmt.Errorf("已有同步任务在进行中")
	}
	syncStatus = SyncStatus{InProgress: true, SourceID: src.ID, StartedAt: time.Now()}
	syncMu.Unlock()

	finish := func(entries int, n int64, err error) error {
		syncMu.Lock()
		syncStatus.InProgress = false
		syncStatus.FinishedAt = time.Now()
		syncStatus.Entries = entries
		syncStatus.BytesRead = n
		if err != nil {
			syncStatus.Err = err.Error()
		}
		syncMu.Unlock()
		return err
	}

	if err := os.MkdirAll(DataDir(), 0o755); err != nil {
		return finish(0, 0, fmt.Errorf("创建数据目录: %w", err))
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(src.URL)
	if err != nil {
		return finish(0, 0, fmt.Errorf("下载 %s: %w", src.URL, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return finish(0, 0, fmt.Errorf("下载 %s 返回 %d", src.URL, resp.StatusCode))
	}

	tmp, err := os.CreateTemp(DataDir(), ".sync-*.tmp")
	if err != nil {
		return finish(0, 0, fmt.Errorf("创建临时文件: %w", err))
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 成功时已改名,这里是失败清理

	n, err := io.Copy(tmp, resp.Body)
	tmp.Close()
	if err != nil {
		return finish(0, n, fmt.Errorf("写入临时文件: %w", err))
	}

	// 先解析验证再启用。解析失败说明格式不符或文件损坏,
	// 此时旧库仍在服务 —— 不能因为一次同步失败就让功能不可用。
	normalized := tmpName + ".norm"
	entries, err := normalize(tmpName, normalized, src.Format)
	if err != nil {
		return finish(0, n, fmt.Errorf("解析 %s 数据: %w", src.Format, err))
	}
	defer os.Remove(normalized)

	if err := os.Rename(normalized, ActivePath()); err != nil {
		return finish(entries, n, fmt.Errorf("启用新库: %w", err))
	}

	if err := Reload(); err != nil {
		return finish(entries, n, fmt.Errorf("重新加载: %w", err))
	}
	return finish(entries, n, nil)
}

// ImportUpload 处理界面上传的文件(隔离网环境的主路径)
func ImportUpload(r io.Reader, format string) (int, error) {
	if err := os.MkdirAll(DataDir(), 0o755); err != nil {
		return 0, fmt.Errorf("创建数据目录: %w", err)
	}

	tmp, err := os.CreateTemp(DataDir(), ".upload-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("创建临时文件: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return 0, fmt.Errorf("接收上传: %w", err)
	}
	tmp.Close()

	normalized := tmpName + ".norm"
	entries, err := normalize(tmpName, normalized, format)
	if err != nil {
		return 0, fmt.Errorf("解析上传文件: %w", err)
	}
	defer os.Remove(normalized)

	if err := os.Rename(normalized, ActivePath()); err != nil {
		return entries, fmt.Errorf("启用新库: %w", err)
	}
	if err := Reload(); err != nil {
		return entries, fmt.Errorf("重新加载: %w", err)
	}
	return entries, nil
}

// Reload 重新加载生效库 + 本地覆盖,并原子替换全局实例。
func Reload() error {
	db, err := Load(ActivePath())
	if err != nil {
		return err
	}
	if n, err := db.applyOverrides(OverridePath()); err != nil {
		// 覆盖文件有问题不应让整库不可用,但必须让用户知道
		return fmt.Errorf("主库已加载,但本地覆盖文件有误(已忽略): %w", err)
	} else if n > 0 {
		db.overrideCount = n
	}
	SetGlobal(db)
	return nil
}

// normalize 把各家格式统一成内部 TSV:start_ip end_ip asn country as_name
//
// 统一格式而不是在查询时分支处理:格式差异只在导入时付一次代价,
// 之后所有查询路径都只面对一种布局。
func normalize(inPath, outPath, format string) (int, error) {
	in, err := openMaybeGzip(inPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	bw := bufio.NewWriterSize(out, 1<<20)
	defer bw.Flush()

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	count := 0
	switch format {
	case "ip2asn_tsv":
		for sc.Scan() {
			line := sc.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// 已是目标格式,仅校验前两列可解析
			f := strings.Split(line, "\t")
			if len(f) < 4 {
				continue
			}
			if net.ParseIP(strings.TrimSpace(f[0])) == nil {
				continue
			}
			if _, err := bw.WriteString(line + "\n"); err != nil {
				return count, err
			}
			count++
		}

	case "rir_delegated":
		// RIR 格式: registry|cc|type|start|value|date|status[|opaque-id]
		// value 对 ipv4 是地址个数(不一定是 2 的幂)
		for sc.Scan() {
			line := sc.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Split(line, "|")
			if len(f) < 7 || f[2] != "ipv4" {
				continue
			}
			cc := strings.ToUpper(strings.TrimSpace(f[1]))
			startIP := net.ParseIP(strings.TrimSpace(f[3]))
			cnt, err := strconv.ParseUint(strings.TrimSpace(f[4]), 10, 32)
			if err != nil || startIP == nil || cnt == 0 {
				continue
			}
			s4 := startIP.To4()
			if s4 == nil {
				continue
			}
			start := binary.BigEndian.Uint32(s4)
			end := start + uint32(cnt-1)
			if end < start {
				continue // 溢出,跳过异常记录
			}
			// RIR 数据不含 AS 号,填 0;国家取注册国
			_, err = fmt.Fprintf(bw, "%s\t%s\t0\t%s\tRIR-%s\n",
				u32ToAddr(start), u32ToAddr(end), cc, strings.TrimSpace(f[0]))
			if err != nil {
				return count, err
			}
			count++
		}

	default:
		return 0, fmt.Errorf("未知格式 %q(支持 ip2asn_tsv / rir_delegated)", format)
	}

	if err := sc.Err(); err != nil {
		return count, err
	}
	if count == 0 {
		return 0, fmt.Errorf("未解析出任何有效记录,请确认格式选择正确")
	}
	return count, nil
}

// ValidateOverrides 校验本地规则文本,不落盘。
//
// 存在理由:界面保存前必须验一遍。写坏的覆盖文件会让下次启动时
// 整库加载失败 —— 一个手滑的空格换来功能全挂,不可接受。
func ValidateOverrides(r io.Reader) error {
	sc := bufio.NewScanner(r)
	lineNo := 0
	valid := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := parseOverrideLine(line); err != nil {
			return fmt.Errorf("第 %d 行: %w", lineNo, err)
		}
		valid++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

// ---- 本地覆盖 ----

// Override 一条本地优先规则
type Override struct {
	Start   uint32
	End     uint32
	ASN     uint32
	Country string
	Note    string
}

// applyOverrides 读取本地规则并覆盖主库中的重叠部分。
//
// 语义:本地规则**完全覆盖**其地址范围内的归属判定。
// 实现上不修改主库条目(会破坏排序),而是追加为独立条目并让
// 查询时优先命中 —— 但当前 Resolve 是按索引集合展开,
// 所以这里采用"先剔除重叠再追加"的做法,保证同一地址不被两次归属。
func (db *DB) applyOverrides(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // 没有覆盖文件是正常状态
		}
		return 0, err
	}
	defer f.Close()

	var ovs []Override
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ov, err := parseOverrideLine(line)
		if err != nil {
			return 0, fmt.Errorf("第 %d 行: %w", lineNo, err)
		}
		ovs = append(ovs, ov)
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if len(ovs) == 0 {
		return 0, nil
	}

	// 剔除与覆盖范围重叠的主库条目,再把覆盖条目并入
	kept := db.entries[:0:len(db.entries)]
	for _, e := range db.entries {
		if overlapsAny(e.Start, e.End, ovs) {
			continue
		}
		kept = append(kept, e)
	}
	for _, ov := range ovs {
		kept = append(kept, Entry{
			Start: ov.Start, End: ov.End, ASN: ov.ASN,
			Country: ov.Country, ASName: ov.Note,
		})
	}
	db.entries = kept
	sort.Slice(db.entries, func(i, j int) bool { return db.entries[i].Start < db.entries[j].Start })
	db.rebuildIndex()

	return len(ovs), nil
}

// parseOverrideLine 解析一行本地规则。
//
// 格式(TSV 或空格分隔,# 起始为注释):
//
//	CIDR或区间   国家码   ASN   备注
//	203.0.113.0/24        CN    4134   实际由本地 ISP 运营
//	1.2.3.0  1.2.3.255    US    0      手工修正
//
// 刻意做得宽松:这个文件是给人手写的,不该因为多一个空格就报错。
func parseOverrideLine(line string) (Override, error) {
	if i := strings.Index(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	f := strings.Fields(strings.ReplaceAll(line, "\t", " "))
	if len(f) < 2 {
		return Override{}, fmt.Errorf("字段不足,至少需要 <范围> <国家码>")
	}

	var start, end uint32
	rest := f[1:]

	if strings.Contains(f[0], "/") {
		_, netw, err := net.ParseCIDR(f[0])
		if err != nil {
			return Override{}, fmt.Errorf("CIDR 非法: %q", f[0])
		}
		ip4 := netw.IP.To4()
		if ip4 == nil {
			return Override{}, fmt.Errorf("暂只支持 IPv4: %q", f[0])
		}
		ones, bits := netw.Mask.Size()
		if bits != 32 {
			return Override{}, fmt.Errorf("暂只支持 IPv4: %q", f[0])
		}
		start = binary.BigEndian.Uint32(ip4)
		size := uint64(1) << (32 - ones)
		end = uint32(uint64(start) + size - 1)
	} else {
		// 区间写法需要两个地址
		if len(f) < 3 {
			return Override{}, fmt.Errorf("区间写法需要 <起始IP> <结束IP> <国家码>")
		}
		s := net.ParseIP(f[0])
		e := net.ParseIP(f[1])
		if s == nil || e == nil || s.To4() == nil || e.To4() == nil {
			return Override{}, fmt.Errorf("IP 地址非法: %q %q", f[0], f[1])
		}
		start = binary.BigEndian.Uint32(s.To4())
		end = binary.BigEndian.Uint32(e.To4())
		if end < start {
			return Override{}, fmt.Errorf("结束地址小于起始地址")
		}
		rest = f[2:]
	}

	ov := Override{Start: start, End: end}
	if len(rest) >= 1 {
		ov.Country = strings.ToUpper(rest[0])
	}
	if len(rest) >= 2 {
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(rest[1]), "AS"), 10, 32); err == nil {
			ov.ASN = uint32(n)
		}
	}
	if len(rest) >= 3 {
		ov.Note = strings.Join(rest[2:], " ")
	}
	if ov.Note == "" {
		ov.Note = "本地覆盖"
	}
	return ov, nil
}

func overlapsAny(start, end uint32, ovs []Override) bool {
	for _, o := range ovs {
		if start <= o.End && o.Start <= end {
			return true
		}
	}
	return false
}
