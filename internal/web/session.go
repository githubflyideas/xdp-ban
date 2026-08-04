package web

import (
	"sync"
	"time"
)

// sessionStore 是会话表。
//
// 为什么需要锁:Gin 每个请求一个 goroutine,登录写、鉴权读会并发命中同一张表。
// Go 的内置 map 并发写会触发 fatal error: concurrent map writes ——
// 这个错误无法 recover,进程直接退出。也就是说没有锁的话,
// "多人同时登录"就是一个可远程触发的拒绝服务。
//
// 为什么不用 sync.Map:这里读写比接近(登录写、每请求读),且需要按过期时间
// 批量清理,RWMutex + 普通 map 更直白也更快。
//
// 单实例内存存储的取舍:重启即失效(所有人需重新登录),不支持多副本。
// 这与项目"单二进制、单机部署"的定位一致;要横向扩展应换成签名 cookie
// 或外部 KV,那属于部署形态变更,不是这一层的补丁。
type sessionStore struct {
	mu   sync.RWMutex
	data map[string]sessionEntry
	ttl  time.Duration
}

type sessionEntry struct {
	userID    uint
	expiresAt time.Time
}

func newSessionStore(ttl time.Duration) *sessionStore {
	s := &sessionStore{
		data: make(map[string]sessionEntry),
		ttl:  ttl,
	}
	go s.reaper()
	return s
}

// Put 建立会话
func (s *sessionStore) Put(token string, userID uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[token] = sessionEntry{userID: userID, expiresAt: time.Now().Add(s.ttl)}
}

// Get 查会话。过期的当作不存在,并顺手删掉。
func (s *sessionStore) Get(token string) (uint, bool) {
	s.mu.RLock()
	e, ok := s.data[token]
	s.mu.RUnlock()

	if !ok {
		return 0, false
	}
	if time.Now().After(e.expiresAt) {
		s.Delete(token)
		return 0, false
	}
	return e.userID, true
}

// Delete 吊销会话(登出)
func (s *sessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
}

// DeleteByUser 吊销某用户的全部会话。
// 改密码、停用账号后必须调用,否则旧 cookie 仍然有效。
func (s *sessionStore) DeleteByUser(userID uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, e := range s.data {
		if e.userID == userID {
			delete(s.data, tok)
		}
	}
}

// reaper 定期清理过期会话,避免长期运行后 map 无界增长。
// 只有被访问过的会话才会在 Get 里被顺带清理,没人再碰的僵尸会话得靠这里。
func (s *sessionStore) reaper() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for tok, e := range s.data {
			if now.After(e.expiresAt) {
				delete(s.data, tok)
			}
		}
		s.mu.Unlock()
	}
}
