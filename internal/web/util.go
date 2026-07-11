package web

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
)

func randToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}
func itoa(u uint) string { return strconv.FormatUint(uint64(u), 10) }
