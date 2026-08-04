// Package config —— 配置管理
package config

import (
	"os"
)

// Config 全局配置
type Config struct {
	DBPath       string
	Listen       string
	BaseURL      string
	MailServer   string
	MailFrom     string
	APIKey       string
	LogLevel     string
}

// Load 从环境变量加载
func Load() *Config {
	return &Config{
		DBPath:     os.Getenv("XDPBAN_DB"),
		Listen:     getEnv("XDPBAN_LISTEN", ":8080"),
		BaseURL:    getEnv("XDPBAN_BASE_URL", "http://localhost:8080"),
		MailServer: getEnv("XDPBAN_MAIL_SERVER", ""),
		MailFrom:   getEnv("XDPBAN_MAIL_FROM", "xdpban@example.com"),
		APIKey:     getEnv("XDPBAN_API_KEY", "changeme"),
		LogLevel:   getEnv("XDPBAN_LOG_LEVEL", "info"),
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
