package banmap

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 这个测试解析 bpf/xdp_filter.c,断言 Go 侧常量声明的 map 名与
// C 侧 SEC(".maps") 定义的完全一致。
//
// 为什么需要它:map 名是运行时字符串查找,编译器抓不到不一致。
// 此前正是因为 C 侧从 ban_list 改成 target_hosts + src_ban 而 Go 侧没跟上,
// 导致 agent 启动即 Fatalf —— 编译通过、测试全绿,执行面却是死的。
// 现在把这条契约变成编译期就能跑的断言。
func TestMapNamesMatchBPFSource(t *testing.T) {
	src := findBPFSource(t, "xdp_filter.c")

	defined := parseMapNames(t, src)
	sort.Strings(defined)

	declared := []string{MapCounters, MapGlobalBans, MapSrcBans, MapTargetHosts}
	sort.Strings(declared)

	if strings.Join(defined, ",") != strings.Join(declared, ",") {
		t.Errorf("map 名不一致:\n  C 侧定义: %v\n  Go 侧声明: %v\n"+
			"这类不一致编译期抓不到,运行时表现为 agent 启动失败或规则静默不生效",
			defined, declared)
	}
}

// 结构体尺寸也是跨语言契约。C 侧字段增删会让 Go 侧编码错位,
// 写进去的 key 与内核算出的不等 —— 黑名单静默失效。
func TestKeyValueSizesMatchBPFSource(t *testing.T) {
	src := findBPFSource(t, "xdp_filter.c")
	body := readFile(t, src)

	// 从 C 源码统计各结构体的字段宽度,与 Go 侧常量比对
	cases := []struct {
		structName string
		goSize     int
	}{
		{"global_ban_key", GlobalKeySize},
		{"src_ban_key", SrcKeySize},
		{"target_key", TargetKeySize},
		{"ban_value", ValueSize},
	}

	for _, tc := range cases {
		got, err := cStructSize(body, tc.structName)
		if err != nil {
			t.Errorf("解析 struct %s: %v", tc.structName, err)
			continue
		}
		if got != tc.goSize {
			t.Errorf("struct %s: C 侧 %d 字节,Go 侧常量 %d 字节 —— "+
				"不一致会导致 key/value 编码错位,规则静默失效",
				tc.structName, got, tc.goSize)
		}
	}
}

// 容量上限必须与 internal/quota 的记账一致,否则用户态以为还有余量
// 而内核已满,插入返回 E2BIG。
func TestMaxSrcBansMatchesQuotaCapacity(t *testing.T) {
	src := findBPFSource(t, "xdp_filter.c")
	body := readFile(t, src)

	re := regexp.MustCompile(`#define\s+MAX_SRC_BANS\s+(\d+)`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("未在 C 源码中找到 MAX_SRC_BANS")
	}

	var cVal int
	fmt.Sscanf(m[1], "%d", &cVal)

	// quota.MapCapacity 必须等于这个值。这里用字面量而非导入 quota
	// 是为了避免 banmap → quota 的反向依赖;数值不一致时测试会失败并提示。
	const quotaMapCapacity = 262144
	if cVal != quotaMapCapacity {
		t.Errorf("MAX_SRC_BANS(C)=%d 与 quota.MapCapacity=%d 不一致 —— "+
			"配额预检会算错余量,最终在下发时收到 E2BIG 而规则静默不生效",
			cVal, quotaMapCapacity)
	}
}

// ---- 辅助 ----

func findBPFSource(t *testing.T, name string) string {
	t.Helper()
	// 从当前包目录向上找到仓库根的 bpf/ 目录
	for _, rel := range []string{
		filepath.Join("..", "..", "bpf", name),
		filepath.Join("..", "bpf", name),
		filepath.Join("bpf", name),
	} {
		if _, err := os.Stat(rel); err == nil {
			return rel
		}
	}
	t.Fatalf("找不到 bpf/%s —— 测试需要读 C 源码来校验跨语言契约", name)
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	return string(b)
}

// parseMapNames 提取 "} <name> SEC(\".maps\");" 中的 name
func parseMapNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开 %s: %v", path, err)
	}
	defer f.Close()

	re := regexp.MustCompile(`^\}\s*(\w+)\s+SEC\("\.maps"\)`)
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := re.FindStringSubmatch(sc.Text()); m != nil {
			names = append(names, m[1])
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("扫描 %s: %v", path, err)
	}
	if len(names) == 0 {
		t.Fatalf("%s 中未解析出任何 map 定义", path)
	}
	return names
}

// cStructSize 粗略计算 C 结构体大小:累加字段宽度,再按 8 字节对齐向上取整。
//
// 只处理本项目实际用到的定长整型字段。刻意不做通用 C 解析 ——
// 那样复杂度远超收益,而这里只需要能抓住"有人加了个字段却忘了改 Go 侧"。
func cStructSize(body, name string) (int, error) {
	re := regexp.MustCompile(`struct\s+` + regexp.QuoteMeta(name) + `\s*\{([^}]*)\}`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return 0, fmt.Errorf("未找到定义")
	}

	widths := map[string]int{
		"__u8": 1, "__u16": 2, "__u32": 4, "__u64": 8,
	}

	total := 0
	maxAlign := 1
	for _, line := range strings.Split(m[1], "\n") {
		// 去掉注释
		if i := strings.Index(line, "/*"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasSuffix(line, ";") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(line, ";"))
		if len(fields) < 2 {
			continue
		}
		w, ok := widths[fields[0]]
		if !ok {
			return 0, fmt.Errorf("未知字段类型 %q", fields[0])
		}
		if w > maxAlign {
			maxAlign = w
		}
		// 处理数组声明,如 _pad[3]
		count := 1
		decl := fields[1]
		if i := strings.Index(decl, "["); i >= 0 {
			j := strings.Index(decl, "]")
			if j > i {
				fmt.Sscanf(decl[i+1:j], "%d", &count)
			}
		}
		total += w * count
	}

	// 按最宽字段对齐向上取整
	if rem := total % maxAlign; rem != 0 {
		total += maxAlign - rem
	}
	return total, nil
}
