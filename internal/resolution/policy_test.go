package resolution

import (
	"strings"
	"testing"
)

func TestAllowlistBeatsBlacklist(t *testing.T) {
	r := Resolve([]string{"allowlist", "blacklist_manual"}, false)
	if r.Effect != Pass { t.Fatal("白名单应压过黑名单") }
}
func TestManualBeatsBlackhole(t *testing.T) {
	r := Resolve([]string{"blacklist_manual", "blacklist_blackhole"}, false)
	if r.DecidedBy != "blacklist_manual" || r.Effect != Drop { t.Fatal("manual 应优先") }
}
func TestSafetyVetoBeatsAll(t *testing.T) {
	r := Resolve([]string{"blacklist_manual"}, true)
	if r.Effect != Pass || r.DecidedBy != "__safety__" { t.Fatal("安全否决应压一切") }
}
func TestHonestFeedback_BannedButWhitelisted(t *testing.T) {
	r := Resolve([]string{"allowlist", "blacklist_manual"}, false)
	if !strings.Contains(Explain("ban", r), "未拦截") { t.Fatal("应警告未拦截") }
}
func TestHonestFeedback_UnbannedButStillCovered(t *testing.T) {
	r := Resolve([]string{"blacklist_blackhole"}, false)
	if !strings.Contains(Explain("unban", r), "仍被") { t.Fatal("应警告仍被拦") }
}
