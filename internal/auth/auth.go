// Package auth —— LDAP 集成(占位)与本地认证
package auth

import (
	"log"

	"github.com/xdpban/xdp-ban/internal/model"
)

// Authenticator 认证接口
type Authenticator interface {
	Authenticate(username, password string) (*model.User, error)
}

// LocalAuth 本地密码认证
type LocalAuth struct{}

func (la *LocalAuth) Authenticate(username, password string) (*model.User, error) {
	// 由 model.User 的 CheckPassword 负责
	log.Printf("[AUTH] local auth for %s", username)
	return nil, nil // 上游(handler)处理
}

// LDAPAuth 占位(待集成)
type LDAPAuth struct {
	server string
	port   int
}

func (la *LDAPAuth) Authenticate(username, password string) (*model.User, error) {
	log.Printf("[AUTH] LDAP auth for %s (NOT IMPLEMENTED)", username)
	return nil, nil
}
