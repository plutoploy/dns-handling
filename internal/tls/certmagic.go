package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"plutoploy/tls/internal/dns"
)

type CertMagicManager struct {
	cache     *certmagic.Cache
	configs   map[string]*certmagic.Config
	configsMu sync.RWMutex
	resolver  *dns.DynamicResolver
	email     string
	ca        string
	storage   certmagic.Storage
	logger    *zap.Logger
}

type ManagerConfig struct {
	Email    string
	CA       string
	Storage  certmagic.Storage
	Resolver *dns.DynamicResolver
	Logger   *zap.Logger
}

func NewCertMagicManager(cfg ManagerConfig) *CertMagicManager {
	if cfg.CA == "" {
		cfg.CA = certmagic.LetsEncryptStagingCA
	}

	cacheOpts := certmagic.CacheOptions{}

	cache := certmagic.NewCache(cacheOpts)

	return &CertMagicManager{
		cache:    cache,
		configs:  make(map[string]*certmagic.Config),
		resolver: cfg.Resolver,
		email:    cfg.Email,
		ca:       cfg.CA,
		storage:  cfg.Storage,
		logger:   cfg.Logger,
	}
}

func (m *CertMagicManager) GetConfig(domain string) *certmagic.Config {
	m.configsMu.RLock()
	cfg, ok := m.configs[domain]
	m.configsMu.RUnlock()
	if ok {
		return cfg
	}

	return m.getOrCreateConfig(domain)
}

func (m *CertMagicManager) getOrCreateConfig(domain string) *certmagic.Config {
	m.configsMu.Lock()
	defer m.configsMu.Unlock()

	if cfg, ok := m.configs[domain]; ok {
		return cfg
	}

	cfg := certmagic.New(m.cache, certmagic.Config{
		Storage: m.storage,
	})

	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:     m.ca,
		Email:  m.email,
		Agreed: true,
	})

	cfg.Issuers = []certmagic.Issuer{issuer}

	m.configs[domain] = cfg
	return cfg
}

func (m *CertMagicManager) ObtainCert(ctx context.Context, domain string) error {
	cfg := m.GetConfig(domain)
	return cfg.ObtainCertSync(ctx, domain)
}

func (m *CertMagicManager) RenewCert(ctx context.Context, domain string, force bool) error {
	cfg := m.GetConfig(domain)
	return cfg.RenewCertSync(ctx, domain, force)
}

func (m *CertMagicManager) ManageAsync(ctx context.Context, domains []string) {
	for _, domain := range domains {
		cfg := m.GetConfig(domain)
		go cfg.ManageAsync(ctx, []string{domain})
	}
}

func (m *CertMagicManager) ManageSync(ctx context.Context, domains []string) error {
	for _, domain := range domains {
		cfg := m.GetConfig(domain)
		if err := cfg.ManageSync(ctx, []string{domain}); err != nil {
			return fmt.Errorf("manage %s: %w", domain, err)
		}
	}
	return nil
}

func (m *CertMagicManager) TLSConfig(domain string) *tls.Config {
	cfg := m.GetConfig(domain)
	tlsCfg := cfg.TLSConfig()
	tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)
	return tlsCfg
}

func (m *CertMagicManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cfg := m.GetConfig(hello.ServerName)
	return cfg.GetCertificate(hello)
}

func (m *CertMagicManager) HTTPChallengeHandler(h http.Handler) http.Handler {
	for _, cfg := range m.getAllConfigs() {
		for _, issuer := range cfg.Issuers {
			if am, ok := issuer.(*certmagic.ACMEIssuer); ok {
				h = am.HTTPChallengeHandler(h)
			}
		}
	}
	return h
}

func (m *CertMagicManager) getAllConfigs() []*certmagic.Config {
	m.configsMu.RLock()
	defer m.configsMu.RUnlock()

	configs := make([]*certmagic.Config, 0, len(m.configs))
	for _, cfg := range m.configs {
		configs = append(configs, cfg)
	}
	return configs
}

func (m *CertMagicManager) ManageDynamicDomain(ctx context.Context) (string, error) {
	if m.resolver == nil {
		return "", fmt.Errorf("no dynamic resolver configured")
	}

	domain, err := m.resolver.GetDynamicDomain(ctx)
	if err != nil {
		return "", fmt.Errorf("get dynamic domain: %w", err)
	}

	m.logger.Info("managing dynamic domain", zap.String("domain", domain))

	if err := m.ManageSync(ctx, []string{domain}); err != nil {
		return "", fmt.Errorf("manage dynamic domain: %w", err)
	}

	return domain, nil
}

func (m *CertMagicManager) StartHTTPServer(addr string, handler http.Handler) *http.Server {
	handler = m.HTTPChallengeHandler(handler)

	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func (m *CertMagicManager) StartTLSServer(addr string, handler http.Handler, domain string) (*http.Server, error) {
	tlsCfg := m.TLSConfig(domain)
	handler = m.HTTPChallengeHandler(handler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return srv, nil
}
