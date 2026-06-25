package http

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"plutoploy/tls/internal/acme"
	"plutoploy/tls/internal/certificates"
	"plutoploy/tls/internal/domain"

	"go.uber.org/zap"
)

type memoryDomainRepo struct {
	mu      sync.Mutex
	domains map[string]*domain.Domain
}

func newMemoryDomainRepo() *memoryDomainRepo {
	return &memoryDomainRepo{domains: make(map[string]*domain.Domain)}
}

func (r *memoryDomainRepo) Create(ctx context.Context, d *domain.Domain) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domains[d.ID] = cloneDomain(d)
	return nil
}

func (r *memoryDomainRepo) GetByID(ctx context.Context, id string) (*domain.Domain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.domains[id]
	if !ok {
		return nil, errors.New("domain not found")
	}
	return cloneDomain(d), nil
}

func (r *memoryDomainRepo) GetByDomainName(ctx context.Context, name string) (*domain.Domain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.domains {
		if d.DomainName == name {
			return cloneDomain(d), nil
		}
	}
	return nil, errors.New("domain not found")
}

func (r *memoryDomainRepo) ListByStatus(ctx context.Context, status domain.Status) ([]*domain.Domain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.Domain
	for _, d := range r.domains {
		if d.Status == status {
			out = append(out, cloneDomain(d))
		}
	}
	return out, nil
}

func (r *memoryDomainRepo) Update(ctx context.Context, d *domain.Domain) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domains[d.ID] = cloneDomain(d)
	return nil
}

func cloneDomain(d *domain.Domain) *domain.Domain {
	if d == nil {
		return nil
	}
	out := *d
	if d.VerifiedAt != nil {
		t := *d.VerifiedAt
		out.VerifiedAt = &t
	}
	return &out
}

type memoryCertRepo struct {
	mu           sync.Mutex
	certificates map[string]*certificates.Certificate
}

func newMemoryCertRepo() *memoryCertRepo {
	return &memoryCertRepo{certificates: make(map[string]*certificates.Certificate)}
}

func (r *memoryCertRepo) Create(ctx context.Context, c *certificates.Certificate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.certificates[c.DomainID] = cloneCertificate(c)
	return nil
}

func (r *memoryCertRepo) GetByDomainID(ctx context.Context, domainID string) (*certificates.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.certificates[domainID]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return cloneCertificate(c), nil
}

func (r *memoryCertRepo) GetByID(ctx context.Context, id string) (*certificates.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.certificates {
		if c.ID == id {
			return cloneCertificate(c), nil
		}
	}
	return nil, errors.New("certificate not found")
}

func cloneCertificate(c *certificates.Certificate) *certificates.Certificate {
	if c == nil {
		return nil
	}
	out := *c
	return &out
}

type mockACMEProvider struct {
	accountKey crypto.Signer
	accountKID string
	order      *acme.Order
	challenge  *acme.Challenge
	certPEM    string
	keyPEM     string
	issuedAt   time.Time
	expiresAt  time.Time
	startedFor string
	startName  string
}

func (p *mockACMEProvider) SetupAccount(ctx context.Context) (crypto.Signer, string, error) {
	return p.accountKey, p.accountKID, nil
}

func (p *mockACMEProvider) StartOrder(ctx context.Context, domainID, domainName string, accountKey crypto.Signer, accountKID string) (*acme.Order, *acme.Challenge, error) {
	p.startedFor = domainID
	p.startName = domainName
	return p.order, p.challenge, nil
}

func (p *mockACMEProvider) CompleteOrder(ctx context.Context, accountKey crypto.Signer, accountKID, orderID string, ch acme.Challenge) (string, string, time.Time, time.Time, error) {
	return p.certPEM, p.keyPEM, p.issuedAt, p.expiresAt, nil
}

func (p *mockACMEProvider) GetOrderByDomainID(ctx context.Context, domainID string) (*acme.Order, error) {
	if p.order != nil && p.order.DomainID == domainID {
		return p.order, nil
	}
	return nil, errors.New("order not found")
}

func (p *mockACMEProvider) GetChallengeByDomainID(ctx context.Context, domainID string) (*acme.Challenge, error) {
	if p.challenge != nil && p.challenge.DomainID == domainID {
		return p.challenge, nil
	}
	return nil, errors.New("challenge not found")
}

type staticTXTResolver struct {
	records map[string][]string
	err     error
}

func (r *staticTXTResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.records[domain], nil
}

func newTestDomainService(t *testing.T, status domain.Status) (*domain.Service, *memoryDomainRepo, string) {
	t.Helper()
	repo := newMemoryDomainRepo()
	domainID := "domain-123"
	repo.domains[domainID] = &domain.Domain{
		ID:                domainID,
		DomainName:        "example.com",
		VerificationToken: "token-123",
		Status:            status,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	return domain.NewService(repo), repo, domainID
}

func TestIssueCertificateCompletesAfterRequestContextEnds(t *testing.T) {
	domainSvc, _, domainID := newTestDomainService(t, domain.StatusVerified)
	certRepo := newMemoryCertRepo()
	certSvc := certificates.NewService(certRepo)

	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	prov := &mockACMEProvider{
		accountKey: accountKey,
		accountKID: "kid-123",
		order: &acme.Order{
			ID:       "order-1",
			DomainID: domainID,
		},
		challenge: &acme.Challenge{
			ID:               "challenge-1",
			DomainID:         domainID,
			AuthorizationURL: "https://acme.test/authz/1",
			ChallengeURL:     "https://acme.test/challenge/1",
			Token:            "token-1",
			KeyAuthorization: "token-1.thumb",
			TXTValue:         "challenge-token",
			Status:           "pending",
		},
		certPEM:   "CERT",
		keyPEM:    "KEY",
		issuedAt:  time.Now().UTC(),
		expiresAt: time.Now().UTC().Add(90 * 24 * time.Hour),
	}

	resolver := &staticTXTResolver{
		records: map[string][]string{
			"_acme-challenge.example.com.": {"challenge-token"},
		},
	}

	h := NewHandler(domainSvc, certSvc, prov, resolver, zap.NewNop(), "example.com", context.Background(), 10*time.Millisecond, 250*time.Millisecond)

	reqCtx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/domains/"+domainID+"/issue-certificate", nil).WithContext(reqCtx)
	req.SetPathValue("id", domainID)
	w := httptest.NewRecorder()

	h.IssueCertificate(w, req)
	cancel()

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusAccepted)
	}

	body, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["order_id"] != "order-1" {
		t.Fatalf("order_id = %v, want %q", resp["order_id"], "order-1")
	}

	waitFor(t, 500*time.Millisecond, func() bool {
		d, err := domainSvc.GetByID(context.Background(), domainID)
		if err != nil {
			return false
		}
		if d.Status != domain.StatusActive {
			return false
		}
		_, err = certSvc.GetByDomainID(context.Background(), domainID)
		return err == nil
	})

	d, err := domainSvc.GetByID(context.Background(), domainID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if d.Status != domain.StatusActive {
		t.Fatalf("domain status = %s, want %s", d.Status, domain.StatusActive)
	}

	cert, err := certSvc.GetByDomainID(context.Background(), domainID)
	if err != nil {
		t.Fatalf("GetByDomainID() error = %v", err)
	}
	if cert.CertificatePEM != "CERT" || cert.PrivateKeyPEM != "KEY" {
		t.Fatalf("unexpected certificate payload: %+v", cert)
	}
}

func TestIssueCertificateTimeoutMarksFailed(t *testing.T) {
	domainSvc, _, domainID := newTestDomainService(t, domain.StatusVerified)
	certRepo := newMemoryCertRepo()
	certSvc := certificates.NewService(certRepo)

	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	prov := &mockACMEProvider{
		accountKey: accountKey,
		accountKID: "kid-123",
		order: &acme.Order{
			ID:       "order-1",
			DomainID: domainID,
		},
		challenge: &acme.Challenge{
			ID:               "challenge-1",
			DomainID:         domainID,
			AuthorizationURL: "https://acme.test/authz/1",
			ChallengeURL:     "https://acme.test/challenge/1",
			Token:            "token-1",
			KeyAuthorization: "token-1.thumb",
			TXTValue:         "challenge-token",
			Status:           "pending",
		},
		certPEM:   "CERT",
		keyPEM:    "KEY",
		issuedAt:  time.Now().UTC(),
		expiresAt: time.Now().UTC().Add(90 * 24 * time.Hour),
	}

	resolver := &staticTXTResolver{
		records: map[string][]string{
			"_acme-challenge.example.com.": {"wrong-token"},
		},
	}

	h := NewHandler(domainSvc, certSvc, prov, resolver, zap.NewNop(), "example.com", context.Background(), 10*time.Millisecond, 80*time.Millisecond)

	req := httptest.NewRequest(http.MethodPost, "/domains/"+domainID+"/issue-certificate", nil)
	req.SetPathValue("id", domainID)
	w := httptest.NewRecorder()

	h.IssueCertificate(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusAccepted)
	}

	waitFor(t, 500*time.Millisecond, func() bool {
		d, err := domainSvc.GetByID(context.Background(), domainID)
		if err != nil {
			return false
		}
		return d.Status == domain.StatusFailed
	})

	d, err := domainSvc.GetByID(context.Background(), domainID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if d.Status != domain.StatusFailed {
		t.Fatalf("domain status = %s, want %s", d.Status, domain.StatusFailed)
	}
	if _, err := certSvc.GetByDomainID(context.Background(), domainID); err == nil {
		t.Fatal("expected no certificate to be stored")
	}
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
