package policy

import "testing"

func TestMatrix_ViewerCannotApprove(t *testing.T) {
	if Allow("viewer", BanRequestApprove) {
		t.Fatal("viewer 不该能审批")
	}
	if !Allow("viewer", BanRequestView) {
		t.Fatal("viewer 应能查看")
	}
}
func TestMatrix_OperatorCannotManageUsers(t *testing.T) {
	if Allow("operator", UserManage) {
		t.Fatal("operator 不该能管用户")
	}
	if !Allow("operator", BanRequestCreate) {
		t.Fatal("operator 应能提请求")
	}
}
func TestMatrix_AdminAll(t *testing.T) {
	for _, c := range []Capability{SystemConfig, UserManage, BanRequestApprove} {
		if !Allow("admin", c) {
			t.Fatalf("admin 应有 %s", c)
		}
	}
}
func TestNav_ViewerHidesSystemConfig(t *testing.T) {
	for _, s := range NavSections("viewer") {
		if s.Key == "system" || s.Key == "users" {
			t.Fatal("viewer 导航不该有系统配置/用户管理")
		}
	}
}
