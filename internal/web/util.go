package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
)

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func itoa(u uint) string { return strconv.FormatUint(uint64(u), 10) }

func atoui(s string) (uint, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	return uint(v), err
}

func formatTime(t interface{}) string {
	if t == nil {
		return "-"
	}
	return fmt.Sprintf("%v", t)
}
