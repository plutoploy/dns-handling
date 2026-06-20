package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"plutoploy/tls/internal/acme"
	"plutoploy/tls/internal/certificates"
	"plutoploy/tls/internal/config"
	"plutoploy/tls/internal/database"
	"plutoploy/tls/internal/dns"
	"plutoploy/tls/internal/domain"
	httphandler "plutoploy/tls/internal/http"
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

	domainRepo := database.NewDomainRepository(db)
	domainSvc := domain.NewService(domainRepo)

	acctRepo := database.NewACMEAccountRepository(db)
	orderRepo := database.NewACMEOrderRepository(db)
	challengeRepo := database.NewACMEChallengeRepository(db)

	acmeProv := acme.NewProvider(
		cfg.ACMEDirectory,
		cfg.ACMEEmail,
		orderRepo,
		challengeRepo,
		acctRepo,
		logger,
	)

	certRepo := database.NewCertificateRepository(db)
	certSvc := certificates.NewService(certRepo)

	handler := httphandler.NewHandler(
		domainSvc,
		certSvc,
		acmeProv,
		dnsResolver,
		logger,
		cfg.PollInterval,
		cfg.PollTimeout,
	)

	router := httphandler.NewRouter(handler)

	srv := &http.Server{
		Addr:         cfg.ServerAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("listening", zap.String("addr", cfg.ServerAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	<-quit
	logger.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("shutdown error", zap.Error(err))
	}

	logger.Info("stopped")
}
