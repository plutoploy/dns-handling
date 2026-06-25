package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"plutoploy/tls/internal/dns"
)

type CertMagicManager struct {
	cache    *certmagic.Cache
	config   *certmagic.Config
	resolver *dns.DynamicResolver
	email    string
	ca       string
	storage  certmagic.Storage
	logger   *zap.Logger
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

	m := &CertMagicManager{
		resolver: cfg.Resolver,
		email:    cfg.Email,
		ca:       cfg.CA,
		storage:  cfg.Storage,
		logger:   cfg.Logger,
	}

	cacheOpts := certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return m.config, nil
		},
		Logger: cfg.Logger,
	}

	m.cache = certmagic.NewCache(cacheOpts)

	m.config = certmagic.New(m.cache, certmagic.Config{
		Storage: m.storage,
	})

	issuer := certmagic.NewACMEIssuer(m.config, certmagic.ACMEIssuer{
		CA:     m.ca,
		Email:  m.email,
		Agreed: true,
	})

	m.config.Issuers = []certmagic.Issuer{issuer}

	return m
}

func (m *CertMagicManager) GetConfig(domain string) *certmagic.Config {
	return m.config
}

func (m *CertMagicManager) ObtainCert(ctx context.Context, domain string) error {
	return m.config.ObtainCertSync(ctx, domain)
}

func (m *CertMagicManager) RenewCert(ctx context.Context, domain string, force bool) error {
	return m.config.RenewCertSync(ctx, domain, force)
}

func (m *CertMagicManager) ManageAsync(ctx context.Context, domains []string) {
	go m.config.ManageAsync(ctx, domains)
}

func (m *CertMagicManager) ManageSync(ctx context.Context, domains []string) error {
	if err := m.config.ManageSync(ctx, domains); err != nil {
		return fmt.Errorf("manage %v: %w", domains, err)
	}
	return nil
}

func (m *CertMagicManager) TLSConfig(domain string) *tls.Config {
	tlsCfg := m.config.TLSConfig()
	tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)
	return tlsCfg
}

func (m *CertMagicManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.config.GetCertificate(hello)
}

func (m *CertMagicManager) HTTPChallengeHandler(h http.Handler) http.Handler {
	for _, issuer := range m.config.Issuers {
		if am, ok := issuer.(*certmagic.ACMEIssuer); ok {
			h = am.HTTPChallengeHandler(h)
		}
	}
	return h
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
