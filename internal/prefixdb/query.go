package prefixdb

import (
	"strconv"
	"strings"
)

type asnQuery struct {
	asn     uint32
	keyword string
}

func normalizeASNQuery(q string) asnQuery {
	s := strings.TrimSpace(q)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return asnQuery{asn: uint32(n)}
	}
	return asnQuery{keyword: strings.ToUpper(strings.TrimSpace(q))}
}

func matchASN(asn uint32, name string, q asnQuery) bool {
	if q.asn != 0 {
		return asn == q.asn
	}
	if q.keyword == "" {
		return true
	}
	return strings.Contains(strings.ToUpper(name), q.keyword)
}
