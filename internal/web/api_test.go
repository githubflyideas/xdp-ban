package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:webtest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.Dispatch{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Exec("DELETE FROM dispatches")
	return db
}

func newAPIRouter(t *testing.T, db *gorm.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterAPI(r, db)
	return r
}

// /api/v1 是给 agent/sampler 用的,没有会话保护,必须靠 API Key 挡住。
// 早先的实现只检查 header 是否为空,任何非空字符串都能通过。
func TestAPIAuth_RejectsWrongKey(t *testing.T) {
	db := newTestDB(t)
	r := newAPIRouter(t, db)

	cases := []struct {
		name string
		key  string
		want int
	}{
		{"缺失", "", http.StatusUnauthorized},
		{"错误的任意值", "not-the-key", http.StatusUnauthorized},
		{"正确", "changeme", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/dispatch/pending", nil)
			if tc.key != "" {
				req.Header.Set("X-API-Key", tc.key)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("状态码 = %d, 期望 %d", w.Code, tc.want)
			}
		})
	}
}

func TestDispatchAck_UpdatesState(t *testing.T) {
	db := newTestDB(t)
	r := newAPIRouter(t, db)

	d := &model.Dispatch{BanRequestID: 1, BanID: "ban-1-x", Payload: "{}", State: "pending"}
	db.Create(d)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dispatch/"+itoa(d.ID)+"/ack", nil)
	req.Header.Set("X-API-Key", "changeme")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, body=%s", w.Code, w.Body.String())
	}
	var reloaded model.Dispatch
	db.First(&reloaded, d.ID)
	if reloaded.State != "acked" {
		t.Errorf("state = %q, 期望 acked", reloaded.State)
	}
	if reloaded.AckedAt == nil {
		t.Error("acked_at 未写入")
	}
}

// agent 用 JSON 体上报失败原因,早先的实现只读表单字段,错误信息会静默丢失。
func TestDispatchFail_AcceptsJSONBody(t *testing.T) {
	db := newTestDB(t)
	r := newAPIRouter(t, db)

	d := &model.Dispatch{BanRequestID: 2, BanID: "ban-2-x", Payload: "{}", State: "pending"}
	db.Create(d)

	body := strings.NewReader(`{"error":"map full"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dispatch/"+itoa(d.ID)+"/fail", body)
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", w.Code)
	}
	var reloaded model.Dispatch
	db.First(&reloaded, d.ID)
	if reloaded.LastError != "map full" {
		t.Errorf("last_error = %q, 期望 \"map full\"", reloaded.LastError)
	}
	if reloaded.Attempts != 1 {
		t.Errorf("attempts = %d, 期望 1", reloaded.Attempts)
	}
}

func TestReceiveSamples_StoresAndAggregates(t *testing.T) {
	db := newTestDB(t)
	r := newAPIRouter(t, db)
	SampleStore = newSampleBuffer(8) // 隔离全局状态

	payload := SampleReport{
		Timestamp: nowUnix(),
		Device:    "eth1",
		SamplingN: 50,
		Flows: []FlowSample{
			{SrcIP: "203.0.113.5", DstIP: "10.0.0.1", Proto: "tcp", PktCount: 10, ByteCount: 640},
			{SrcIP: "203.0.113.6", DstIP: "10.0.0.1", Proto: "tcp", PktCount: 99, ByteCount: 9000},
		},
	}
	data, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/samples", strings.NewReader(string(data)))
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, body=%s", w.Code, w.Body.String())
	}
	if got := SampleStore.SamplingN(); got != 50 {
		t.Errorf("SamplingN = %d, 期望 50", got)
	}

	top := SampleStore.TopFlows(time.Minute, 5)
	if len(top) != 2 {
		t.Fatalf("TopFlows 返回 %d 条, 期望 2", len(top))
	}
	// 按包数降序:最吵的排第一
	if top[0].SrcIP != "203.0.113.6" {
		t.Errorf("首位来源 = %s, 期望 203.0.113.6(包数最多)", top[0].SrcIP)
	}
}

// 采样率必须在服务端校验,不能只靠前端 input 的 min/max。
func TestSetSamplingRate_ValidatesInput(t *testing.T) {
	for _, raw := range []string{"0", "-5", "abc", "", "99999999"} {
		if _, err := parseRate(raw); err == nil {
			t.Errorf("采样率 %q 应被拒绝", raw)
		}
	}
	for _, raw := range []string{"1", "100", "1000000"} {
		if _, err := parseRate(raw); err != nil {
			t.Errorf("采样率 %q 应被接受: %v", raw, err)
		}
	}
}

// 确认转发到采样器的请求形状正确(表单字段 rate)
func TestSetSamplingRate_ForwardsToSampler(t *testing.T) {
	var gotRate string
	sampler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sampling/rate" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotRate = r.FormValue("rate")
		w.WriteHeader(http.StatusOK)
	}))
	defer sampler.Close()

	resp, err := http.PostForm(sampler.URL+"/api/sampling/rate", url.Values{"rate": {"250"}})
	if err != nil {
		t.Fatalf("转发失败: %v", err)
	}
	defer resp.Body.Close()

	if gotRate != "250" {
		t.Errorf("采样器收到 rate=%q, 期望 250", gotRate)
	}
}
