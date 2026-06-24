package config

import (
	"os"
	"time"

	"github.com/caddyserver/certmagic"
)

type Config struct {
	DatabaseURL          string
	ACMEEmail            string
	ACMEDirectory        string
	ServerAddr           string
	DNSTimeout           time.Duration
	PollInterval         time.Duration
	PollTimeout          time.Duration
	LogLevel             string
	BaseDomain           string
	HTTPAddr             string
	TLSAddr              string
	DNSAddr              string
	CertMagicStoragePath string
	AuthToken            string
}

func Load() *Config {
	return &Config{
		DatabaseURL:          getEnv("DATABASE_URL", "file:./tls.db"),
		ACMEEmail:            getEnv("ACME_EMAIL", "admin@example.com"),
		ACMEDirectory:        getEnv("ACME_DIRECTORY", certmagic.LetsEncryptStagingCA),
		ServerAddr:           getEnv("SERVER_ADDR", ":8080"),
		DNSTimeout:           10 * time.Second,
		PollInterval:         10 * time.Second,
		PollTimeout:          5 * time.Minute,
		LogLevel:             getEnv("LOG_LEVEL", "info"),
		BaseDomain:           getEnv("BASE_DOMAIN", "example.com"),
		HTTPAddr:             getEnv("HTTP_ADDR", ":80"),
		TLSAddr:              getEnv("TLS_ADDR", ":443"),
		DNSAddr:              getEnv("DNS_ADDR", ":53"),
		CertMagicStoragePath: getEnv("CERTMAGIC_STORAGE_PATH", "./certmagic-data"),
		AuthToken:            getEnv("AUTH_TOKEN", ""),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
