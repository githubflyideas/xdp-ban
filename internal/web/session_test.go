package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
)

func newAuthTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:sesstest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Exec("DELETE FROM users")

	u := &model.User{Username: "admin", Role: "admin", Active: true, AuthSource: "local"}
	_ = u.SetPassword("admin12345")
	db.Create(u)
	return db
}

// 会话表被并发的 Gin handler 同时读写。Go 的内置 map 不是并发安全的,
// 并发写会触发 "concurrent map writes" 致命错误 —— 这个 panic 无法被
// recover,整个进程直接退出。也就是说:多人同时登录就能把服务打挂。
//
// 这个测试在 -race 下必然报告数据竞争(修复前),修复后干净。
func TestSessionStore_ConcurrentLoginAndAccess(t *testing.T) {
	db := newAuthTestDB(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r, db)

	var wg sync.WaitGroup

	// 32 个并发登录(写会话表)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := strings.NewReader("username=admin&password=admin12345")
			req := httptest.NewRequest(http.MethodPost, "/login", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusFound {
				t.Errorf("登录状态码 = %d, 期望 302", w.Code)
			}
		}()
	}

	// 32 个并发受保护页访问(读会话表)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
			req.AddCookie(&http.Cookie{Name: "sid", Value: "bogus-token"})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			// 无效 token 应重定向到登录页,而不是崩溃
			if w.Code != http.StatusFound {
				t.Errorf("未授权访问状态码 = %d, 期望 302", w.Code)
			}
		}()
	}

	wg.Wait()
}

// 登出必须真正吊销会话:同一 token 不能在登出后继续通过鉴权。
func TestSessionStore_LogoutRevokes(t *testing.T) {
	db := newAuthTestDB(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r, db)

	// 登录取 cookie
	body := strings.NewReader("username=admin&password=admin12345")
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var sid string
	for _, c := range w.Result().Cookies() {
		if c.Name == "sid" {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("登录未下发 sid cookie")
	}

	// 带 cookie 访问受保护页 → 应通过
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("登录后访问 dashboard = %d, 期望 200", w.Code)
	}

	// 登出
	req = httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 同一 token 再访问 → 必须被拒
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("登出后仍可访问 dashboard(状态码 %d),会话未吊销", w.Code)
	}
}
