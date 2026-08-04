package escalation

import "testing"

func TestFirstBan10Min(t *testing.T) {
	p := NewPenalty("1.1.1.1")
	if p.RegisterBan(false) != 600 { t.Fatal("首次应 600s") }
	if p.Level != 0 { t.Fatal("首次 level 0") }
}
func TestEscalationSequence(t *testing.T) {
	p := NewPenalty("1.1.1.2")
	want := []int64{600, 3600, 86400, 604800, 0}
	got := []int64{p.RegisterBan(false)}
	for i := 0; i < 4; i++ { got = append(got, p.RegisterBan(true)) }
	for i := range want {
		if got[i] != want[i] { t.Fatalf("阶梯[%d] 期望 %d 得 %d", i, want[i], got[i]) }
	}
	if !p.Permanent() { t.Fatal("末级应永久") }
}
func TestCapNoOverflow(t *testing.T) {
	p := NewPenalty("1.1.1.3")
	for i := 0; i < 20; i++ { p.RegisterBan(true) }
	if p.Level != len(Ladder)-1 { t.Fatal("封顶不溢出") }
}
func TestStillAttacking(t *testing.T) {
	p := NewPenalty("1.1.1.4"); p.BaselinePackets = 100
	if p.StillAttacking(103) { t.Fatal("增量3不算") }
	if !p.StillAttacking(200) { t.Fatal("增量100算") }
}
