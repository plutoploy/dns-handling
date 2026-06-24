package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"plutoploy/tls/internal/acme"
	"plutoploy/tls/internal/certificates"
	"plutoploy/tls/internal/config"
	"plutoploy/tls/internal/database"
	"plutoploy/tls/internal/dns"
	"plutoploy/tls/internal/domain"
	httphandler "plutoploy/tls/internal/http"
	"plutoploy/tls/internal/tls"
)

func main() {
	cfg := config.Load()

	logger, err := zap.NewProduction()
	if err != nil {
		panic(fmt.Errorf("init logger: %w", err))
	}
	defer logger.Sync()

	if cfg.LogLevel == "debug" {
		logger, _ = zap.NewDevelopment()
	}

	logger.Info("starting tls service",
		zap.String("addr", cfg.ServerAddr),
		zap.String("db", cfg.DatabaseURL),
		zap.String("base_domain", cfg.BaseDomain),
	)

	db, err := database.New(cfg.DatabaseURL, logger)
	if err != nil {
		logger.Fatal("database connection", zap.Error(err))
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		logger.Fatal("database migration", zap.Error(err))
	}

	dnsResolver := dns.NewNetResolver(cfg.DNSTimeout)
	dynamicResolver := dns.NewDynamicResolver(cfg.BaseDomain, 5*time.Minute, logger)

	domainRepo := database.NewDomainRepository(db)
	domainSvc := domain.NewService(domainRepo)

	acctRepo := database.NewACMEAccountRepository(db)
	orderRepo := database.NewACMEOrderRepository(db)
	challengeRepo := database.NewACMEChallengeRepository(db)
	certRepo := database.NewCertificateRepository(db)
	certSvc := certificates.NewService(certRepo)
	acmeProv := acme.NewProvider(cfg.ACMEDirectory, cfg.ACMEEmail, orderRepo, challengeRepo, acctRepo, logger)

	certmagicStorage := &certmagic.FileStorage{
		Path: cfg.CertMagicStoragePath,
	}

	magicManager := tls.NewCertMagicManager(tls.ManagerConfig{
		Email:    cfg.ACMEEmail,
		CA:       cfg.ACMEDirectory,
		Storage:  certmagicStorage,
		Resolver: dynamicResolver,
		Logger:   logger,
	})

	dnsSrv := dns.NewDNSServer(dns.DNSServerConfig{
		ListenAddr: cfg.DNSAddr,
		BaseDomain: cfg.BaseDomain,
		Resolver:   dynamicResolver,
		Logger:     logger,
	})

	domainHandler := httphandler.NewHandler(
		domainSvc,
		certSvc,
		acmeProv,
		dnsResolver,
		logger,
		cfg.PollInterval,
		cfg.PollTimeout,
	)

	dnsHandler := httphandler.NewDNSHandler(dnsSrv, logger)

	router := httphandler.NewRouter(domainHandler, dnsHandler, cfg.AuthToken)

	httpSrv := magicManager.StartHTTPServer(cfg.HTTPAddr, router)
	tlsSrv, err := magicManager.StartTLSServer(cfg.TLSAddr, router, cfg.BaseDomain)
	if err != nil {
		logger.Fatal("create TLS server", zap.Error(err))
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("managing dynamic domain")
		if _, err := magicManager.ManageDynamicDomain(context.Background()); err != nil {
			logger.Error("manage dynamic domain", zap.Error(err))
		}
	}()

	go func() {
		logger.Info("DNS server listening", zap.String("addr", cfg.DNSAddr))
		if err := dnsSrv.Start(); err != nil {
			logger.Error("DNS server error", zap.Error(err))
		}
	}()

	go func() {
		logger.Info("HTTP server listening", zap.String("addr", cfg.HTTPAddr))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	go func() {
		logger.Info("TLS server listening", zap.String("addr", cfg.TLSAddr))
		if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("TLS server error", zap.Error(err))
		}
	}()

	<-quit
	logger.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := dnsSrv.Shutdown(); err != nil {
		logger.Error("DNS shutdown error", zap.Error(err))
	}

	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("HTTP shutdown error", zap.Error(err))
	}

	if err := tlsSrv.Shutdown(ctx); err != nil {
		logger.Error("TLS shutdown error", zap.Error(err))
	}

	logger.Info("stopped")
}
