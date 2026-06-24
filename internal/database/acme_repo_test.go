package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"plutoploy/tls/internal/acme"

	"go.uber.org/zap"
)

func TestACMERepositoriesRoundTripDomainID(t *testing.T) {
	sqlDB, err := sql.Open("sqlite", "file:acme-repo-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer sqlDB.Close()

	db := &DB{DB: sqlDB, logger: zap.NewNop()}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	orderRepo := NewACMEOrderRepository(db)
	challengeRepo := NewACMEChallengeRepository(db)

	now := time.Now().UTC().Truncate(time.Second)
	order := &acme.Order{
		ID:        "order-1",
		DomainID:  "domain-1",
		OrderURL:  "https://acme.test/order/1",
		Status:    "pending",
		CreatedAt: now,
	}
	challenge := &acme.Challenge{
		ID:               "challenge-1",
		DomainID:         "domain-1",
		AuthorizationURL: "https://acme.test/authz/1",
		ChallengeURL:     "https://acme.test/challenge/1",
		Token:            "token-1",
		KeyAuthorization: "token-1.thumb",
		TXTValue:         "txt-1",
		Status:           "pending",
		CreatedAt:        now,
	}

	if err := orderRepo.Create(context.Background(), order); err != nil {
		t.Fatalf("orderRepo.Create() error = %v", err)
	}
	if err := challengeRepo.Create(context.Background(), challenge); err != nil {
		t.Fatalf("challengeRepo.Create() error = %v", err)
	}

	gotOrder, err := orderRepo.GetByDomainID(context.Background(), "domain-1")
	if err != nil {
		t.Fatalf("orderRepo.GetByDomainID() error = %v", err)
	}
	if gotOrder.DomainID != "domain-1" {
		t.Fatalf("order DomainID = %q, want %q", gotOrder.DomainID, "domain-1")
	}

	gotChallenge, err := challengeRepo.GetByDomainID(context.Background(), "domain-1")
	if err != nil {
		t.Fatalf("challengeRepo.GetByDomainID() error = %v", err)
	}
	if gotChallenge.DomainID != "domain-1" {
		t.Fatalf("challenge DomainID = %q, want %q", gotChallenge.DomainID, "domain-1")
	}
}
