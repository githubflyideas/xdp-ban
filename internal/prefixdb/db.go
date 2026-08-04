// Package prefixdb —— 国家 / ASN → IP 前缀集的本地数据源。
//
// 数据来源:iptoasn.com 的 ip2asn-v4.tsv(公共领域 PDDL,每小时更新),
// 格式为 `range_start range_end AS_number country_code AS_description`。
// 同类可替换来源:APNIC/RIPE 的 delegated-extended 文件、BGP.HE.NET 导出、
// MaxMind GeoLite2-ASN。选 iptoasn 是因为它同时给出国家与 AS,单文件、
// 无需注册、许可清晰。
//
// 设计要点:数据文件不打进二进制。全球 IPv4 表约 120 万条区间,
// 压缩后约 10 MB、解压 40 MB+,嵌进二进制会让"拷一个文件就能跑"变成谎言。
// 改为运行时按需加载,文件缺失时功能优雅降级(界面提示未导入),
// 而不是让整个程序起不来。
package prefixdb

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry 一条 IP 区间记录
type Entry struct {
	Start   uint32 // 含
	End     uint32 // 含
	ASN     uint32
	Country string // ISO 3166-1 alpha-2,未知为 "None"
	ASName  string
}

// DB 是加载后的前缀数据库(只读,加载后不再变更)
type DB struct {
	entries []Entry // 按 Start 升序,便于二分

	// 索引:国家码 / ASN → entries 下标。避免每次查询全表扫描。
	byCountry map[string][]int
	byASN     map[uint32][]int

	// 元信息,供界面展示"数据新鲜度"
	sourcePath    string
	loadedAt      time.Time
	overrideCount int
}

var (
	global   *DB
	globalMu sync.RWMutex
)

// Global 返回已加载的数据库;未加载时返回 nil。
// 调用方必须处理 nil —— 数据文件是可选的。
func Global() *DB {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// SetGlobal 安装数据库(加载完成后调用)
func SetGlobal(db *DB) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = db
}

// Load 从 ip2asn TSV(可为 .gz)加载。
//
// 内存占用是首要约束:120 万条 Entry × 约 48 字节 ≈ 60 MB,
// 加上两个索引 map 约 20 MB。这是常驻内存,必须让运维知情,
// 因此 Stats() 会把条目数暴露到界面上。
func Load(path string) (*DB, error) {
	r, err := openMaybeGzip(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	db := &DB{
		byCountry:  make(map[string][]int, 256),
		byASN:      make(map[uint32][]int, 100000),
		sourcePath: path,
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 4 {
			continue // 容忍脏行:数据源偶有空行/注释,不因一行坏掉整库
		}
		start := net.ParseIP(strings.TrimSpace(fields[0]))
		end := net.ParseIP(strings.TrimSpace(fields[1]))
		if start == nil || end == nil {
			continue
		}
		s4, e4 := start.To4(), end.To4()
		if s4 == nil || e4 == nil {
			continue // 只处理 IPv4
		}
		asn, _ := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 32)
		country := strings.ToUpper(strings.TrimSpace(fields[3]))
		asName := ""
		if len(fields) >= 5 {
			asName = strings.TrimSpace(fields[4])
		}

		e := Entry{
			Start:   binary.BigEndian.Uint32(s4),
			End:     binary.BigEndian.Uint32(e4),
			ASN:     uint32(asn),
			Country: country,
			ASName:  asName,
		}
		if e.End < e.Start {
			continue
		}

		idx := len(db.entries)
		db.entries = append(db.entries, e)
		if country != "" && country != "NONE" {
			db.byCountry[country] = append(db.byCountry[country], idx)
		}
		if asn != 0 {
			db.byASN[uint32(asn)] = append(db.byASN[uint32(asn)], idx)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取 %s (第 %d 行): %w", path, line, err)
	}
	if len(db.entries) == 0 {
		return nil, fmt.Errorf("%s 未解析出任何有效记录", path)
	}

	sort.Slice(db.entries, func(i, j int) bool { return db.entries[i].Start < db.entries[j].Start })
	db.rebuildIndex()
	db.loadedAt = time.Now()

	return db, nil
}

// rebuildIndex 重建国家 / ASN 索引。
// 排序或合并覆盖规则后必须调用 —— 索引存的是下标,顺序一变就全错。
func (db *DB) rebuildIndex() {
	db.byCountry = make(map[string][]int, 256)
	db.byASN = make(map[uint32][]int, 100000)
	for i := range db.entries {
		e := &db.entries[i]
		if e.Country != "" && e.Country != "NONE" {
			db.byCountry[e.Country] = append(db.byCountry[e.Country], i)
		}
		if e.ASN != 0 {
			db.byASN[e.ASN] = append(db.byASN[e.ASN], i)
		}
	}
}

// Stats 数据库概况,供界面展示
type Stats struct {
	SourcePath    string
	Entries       int
	Countries     int
	ASNs          int
	LoadedAt      time.Time
	OverrideCount int
}

func (db *DB) Stats() Stats {
	return Stats{
		SourcePath:    db.sourcePath,
		Entries:       len(db.entries),
		Countries:     len(db.byCountry),
		ASNs:          len(db.byASN),
		LoadedAt:      db.loadedAt,
		OverrideCount: db.overrideCount,
	}
}

// openMaybeGzip 打开文件,按内容嗅探而非扩展名判断是否 gzip。
//
// 按扩展名判断会在两种常见情形下出错:用户上传时改了文件名、
// 或下载工具自动解压但保留了 .gz 后缀。嗅探魔术字节更可靠。
func openMaybeGzip(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 %s: %w", path, err)
	}

	var magic [2]byte
	n, _ := io.ReadFull(f, magic[:])
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}

	if n == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("解压 %s: %w", path, err)
		}
		return &gzipCloser{gz: gz, f: f}, nil
	}
	return f, nil
}

type gzipCloser struct {
	gz *gzip.Reader
	f  *os.File
}

func (g *gzipCloser) Read(p []byte) (int, error) { return g.gz.Read(p) }
func (g *gzipCloser) Close() error {
	g.gz.Close()
	return g.f.Close()
}
