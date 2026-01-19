package config

import (
	"os"
)

type Config struct {
	Port         string
	DatabasePath string
	JWTSecret    string
	FrpsHost     string
	FrpsPort     string
	FrpsToken    string
	Domain       string
	ResendAPIKey string
	EmailFrom    string
}

func Load() *Config {
	return &Config{
		Port:         getEnv("PORT", "3000"),
		DatabasePath: getEnv("DATABASE_PATH", "data/relay.db"),
		JWTSecret:    getEnv("JWT_SECRET", "change-me-in-production"),
		FrpsHost:     getEnv("FRPS_HOST", "127.0.0.1"),
		FrpsPort:     getEnv("FRPS_PORT", "7000"),
		FrpsToken:    getEnv("FRPS_TOKEN", ""),
		Domain:       getEnv("FRPS_DOMAIN", "liuyao16.dpdns.org"),
		ResendAPIKey: getEnv("RESEND_API_KEY", ""),
		EmailFrom:    getEnv("EMAIL_FROM", "OpenCode <noreply@liuyao16.dpdns.org>"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
