package config

import (
	"os"
	"time"
)

type Config struct {
	DatabaseURL   string
	ACMEEmail     string
	ACMEDirectory string
	ServerAddr    string
	DNSTimeout    time.Duration
	PollInterval  time.Duration
	PollTimeout   time.Duration
	LogLevel      string
}

func Load() *Config {
	return &Config{
		DatabaseURL:   getEnv("DATABASE_URL", "file:./tls.db"),
		ACMEEmail:     getEnv("ACME_EMAIL", "admin@example.com"),
		ACMEDirectory: getEnv("ACME_DIRECTORY", "https://acme-staging-v02.api.letsencrypt.org/directory"),
		ServerAddr:    getEnv("SERVER_ADDR", ":8080"),
		DNSTimeout:    10 * time.Second,
		PollInterval:  10 * time.Second,
		PollTimeout:   5 * time.Minute,
		LogLevel:      getEnv("LOG_LEVEL", "info"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
