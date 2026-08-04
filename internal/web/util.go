package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// 事务内部用于区分失败原因的哨兵错误
var (
	errSelfApproval  = errors.New("self approval")
	errStateConflict = errors.New("state conflict")
)

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func itoa(u uint) string { return strconv.FormatUint(uint64(u), 10) }

// parseRate 校验采样率输入。上界防止误输入把采样降到实际失效,
// 下界防止 0 造成 BPF 侧取模除零。
func parseRate(raw string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("采样率需为整数: %q", raw)
	}
	if n < 1 || n > 1000000 {
		return 0, fmt.Errorf("采样率需在 1..1000000 之间,收到 %d", n)
	}
	return n, nil
}

func nowUnix() int64 { return time.Now().Unix() }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
