package domain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

type mockRepo struct {
	domains map[string]*Domain
}

func newMockRepo() *mockRepo {
	return &mockRepo{domains: make(map[string]*Domain)}
}

func (r *mockRepo) Create(ctx context.Context, d *Domain) error {
	r.domains[d.ID] = d
	return nil
}

func (r *mockRepo) GetByID(ctx context.Context, id string) (*Domain, error) {
	d, ok := r.domains[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return d, nil
}

func (r *mockRepo) GetByDomainName(ctx context.Context, name string) (*Domain, error) {
	for _, d := range r.domains {
		if d.DomainName == name {
			return d, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (r *mockRepo) ListByStatus(ctx context.Context, status Status) ([]*Domain, error) {
	var out []*Domain
	for _, d := range r.domains {
		if d.Status == status {
			out = append(out, d)
		}
	}
	return out, nil
}

func (r *mockRepo) Update(ctx context.Context, d *Domain) error {
	r.domains[d.ID] = d
	return nil
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	if len(token) != 32 {
		t.Errorf("expected token length 32, got %d", len(token))
	}
}

func TestGenerateTokenUnique(t *testing.T) {
	t1, _ := GenerateToken()
	t2, _ := GenerateToken()
	if t1 == t2 {
		t.Errorf("expected unique tokens, got identical")
	}
}

func TestCreate(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo)

	// override newID for deterministic test
	newID = func() string { return "test-id-1" }

	d, err := svc.Create(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if d.DomainName != "example.com" {
		t.Errorf("expected domain name example.com, got %s", d.DomainName)
	}
	if d.Status != StatusPending {
		t.Errorf("expected status pending, got %s", d.Status)
	}
	if d.VerificationToken == "" {
		t.Errorf("expected non-empty verification token")
	}
}

func TestVerifyTXTSuccess(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo)

	token := "test-token"
	d := &Domain{
		ID:                "test-id",
		DomainName:        "example.com",
		VerificationToken: token,
		Status:            StatusPending,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	repo.domains[d.ID] = d

	updated, err := svc.VerifyTXT(context.Background(), "test-id", []string{token, "other-record"})
	if err != nil {
		t.Fatalf("VerifyTXT() error = %v", err)
	}

	if updated.Status != StatusVerified {
		t.Errorf("expected status verified, got %s", updated.Status)
	}
	if updated.VerifiedAt == nil {
		t.Errorf("expected verified_at to be set")
	}
}

func TestVerifyTXTFailureNoMatch(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo)

	d := &Domain{
		ID:                "test-id",
		DomainName:        "example.com",
		VerificationToken: "expected-token",
		Status:            StatusPending,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	repo.domains[d.ID] = d

	_, err := svc.VerifyTXT(context.Background(), "test-id", []string{"wrong-token"})
	if err == nil {
		t.Fatal("expected error for mismatched token")
	}
}

func TestVerifyTXTFailureWrongStatus(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo)

	d := &Domain{
		ID:                "test-id",
		DomainName:        "example.com",
		VerificationToken: "token",
		Status:            StatusVerified,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	repo.domains[d.ID] = d

	_, err := svc.VerifyTXT(context.Background(), "test-id", []string{"token"})
	if err == nil {
		t.Fatal("expected error for already verified domain")
	}
}

func TestChallengeDomain(t *testing.T) {
	svc := NewService(nil)

	domain := svc.ChallengeDomain("example.com")
	expected := "_acme-challenge.example.com."
	if domain != expected {
		t.Errorf("expected %s, got %s", expected, domain)
	}
}

func TestStatusTransitions(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo)

	d := &Domain{
		ID:                "test-id",
		DomainName:        "example.com",
		VerificationToken: "token",
		Status:            StatusVerified,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	repo.domains[d.ID] = d

	updated, err := svc.SetCertificatePending(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("SetCertificatePending() error = %v", err)
	}
	if updated.Status != StatusCertificatePending {
		t.Errorf("expected status certificate_pending, got %s", updated.Status)
	}

	updated, err = svc.SetActive(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("SetActive() error = %v", err)
	}
	if updated.Status != StatusActive {
		t.Errorf("expected status active, got %s", updated.Status)
	}

	updated, err = svc.SetFailed(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("SetFailed() error = %v", err)
	}
	if updated.Status != StatusFailed {
		t.Errorf("expected status failed, got %s", updated.Status)
	}
}

func TestSetCertificatePendingRequiresVerified(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo)

	d := &Domain{
		ID:                "test-id",
		DomainName:        "example.com",
		VerificationToken: "token",
		Status:            StatusPending,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	repo.domains[d.ID] = d

	_, err := svc.SetCertificatePending(context.Background(), "test-id")
	if err == nil {
		t.Fatal("expected error when domain is not verified")
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		records []string
		target  string
		want    bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{[]string{}, "a", false},
		{[]string{"same"}, "same", true},
	}

	for _, tt := range tests {
		got := contains(tt.records, tt.target)
		if got != tt.want {
			t.Errorf("contains(%v, %s) = %v, want %v", tt.records, tt.target, got, tt.want)
		}
	}
}

func init() {
	newID = func() string {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
}
