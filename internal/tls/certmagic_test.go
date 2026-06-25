package tls

import (
	"time"
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap/zaptest"

	"plutoploy/tls/internal/dns"
)

func TestNewCertMagicManager(t *testing.T) {
	logger := zaptest.NewLogger(t)

	storage := &certmagic.FileStorage{
		Path: t.TempDir(),
	}
	resolver := dns.NewDynamicResolver("example.com", time.Minute, logger)

	// This should not panic
	manager, err := NewCertMagicManager(ManagerConfig{
		Email:   "test@example.com",
		CA:      certmagic.LetsEncryptStagingCA,
		Storage: storage,
		Resolver: resolver,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("NewCertMagicManager() error = %v", err)
	}

	if manager == nil {
		t.Fatal("expected manager to be non-nil")
	}

	// Check GetConfig
	cfg1 := manager.GetConfig("example.com")
	if cfg1 == nil {
		t.Fatal("expected config to be non-nil")
	}

	// Verify caching of configs
	cfg2 := manager.GetConfig("example.com")
	if cfg1 != cfg2 {
		t.Error("expected GetConfig to return the same instance for the same domain")
	}
}
