package safety

import "testing"

func TestVeto_ProtectedIP(t *testing.T) {
	g := New([]string{"8.8.8.8"})
	if g.AssertSafe("8.8.8.8") == nil {
		t.Fatal("受保护 IP 应被否决")
	}
}
func TestVeto_BigRangeCoveringProtected(t *testing.T) {
	g := New([]string{"8.8.8.8"})
	if g.AssertSafe("8.8.8.0/24") == nil {
		t.Fatal("覆盖受保护IP的大段应被否决")
	}
}
func TestVeto_Loopback(t *testing.T) {
	g := New(nil)
	if g.AssertSafe("127.0.0.1") == nil {
		t.Fatal("环回应被硬编码保护")
	}
}
func TestVeto_WholeInternet(t *testing.T) {
	g := New([]string{"8.8.8.8"})
	if g.AssertSafe("0.0.0.0/0") == nil {
		t.Fatal("0.0.0.0/0 应被否决(防封全网)")
	}
}
func TestPass_Unrelated(t *testing.T) {
	g := New([]string{"8.8.8.8"})
	if g.AssertSafe("203.0.113.44") != nil {
		t.Fatal("无关 IP 应放行")
	}
}
func TestVeto_Malformed(t *testing.T) {
	g := New(nil)
	if g.AssertSafe("not-an-ip") == nil {
		t.Fatal("非法目标应保守否决")
	}
}
