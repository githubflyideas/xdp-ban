package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
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

func nowUnix() int64 { return time.Now().Unix() }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
