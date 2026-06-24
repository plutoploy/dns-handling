package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	acmeclient "github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

type fakeOrderRepo struct {
	created []*Order
}

func (r *fakeOrderRepo) Create(ctx context.Context, o *Order) error {
	r.created = append(r.created, o)
	return nil
}

func (r *fakeOrderRepo) GetByDomainID(ctx context.Context, domainID string) (*Order, error) {
	for i := len(r.created) - 1; i >= 0; i-- {
		if r.created[i].DomainID == domainID {
			return r.created[i], nil
		}
	}
	return nil, context.Canceled
}

func (r *fakeOrderRepo) GetByID(ctx context.Context, id string) (*Order, error) {
	for i := len(r.created) - 1; i >= 0; i-- {
		if r.created[i].ID == id {
			return r.created[i], nil
		}
	}
	return nil, context.Canceled
}

func (r *fakeOrderRepo) Update(ctx context.Context, o *Order) error { return nil }

type fakeChallengeRepo struct {
	created []*Challenge
}

func (r *fakeChallengeRepo) Create(ctx context.Context, c *Challenge) error {
	r.created = append(r.created, c)
	return nil
}

func (r *fakeChallengeRepo) GetByDomainID(ctx context.Context, domainID string) (*Challenge, error) {
	for i := len(r.created) - 1; i >= 0; i-- {
		if r.created[i].DomainID == domainID {
			return r.created[i], nil
		}
	}
	return nil, context.Canceled
}

func (r *fakeChallengeRepo) Update(ctx context.Context, c *Challenge) error { return nil }

type fakeAccountRepo struct {
	account *Account
}

func (r *fakeAccountRepo) Get(ctx context.Context) (*Account, error) { return r.account, nil }
func (r *fakeAccountRepo) Save(ctx context.Context, a *Account) error {
	r.account = a
	return nil
}

type fakeACMEClient struct {
	order         acmeclient.Order
	authz         acmeclient.Authorization
	finalized     acmeclient.Order
	certs         []acmeclient.Certificate
	newOrderSeen  acmeclient.Order
	authzSeen     string
	challengeSeen acmeclient.Challenge
}

func (c *fakeACMEClient) NewAccount(ctx context.Context, account acmeclient.Account) (acmeclient.Account, error) {
	return acmeclient.Account{Location: "acct-url"}, nil
}

func (c *fakeACMEClient) NewOrder(ctx context.Context, account acmeclient.Account, order acmeclient.Order) (acmeclient.Order, error) {
	c.newOrderSeen = order
	return c.order, nil
}

func (c *fakeACMEClient) GetAuthorization(ctx context.Context, account acmeclient.Account, authzURL string) (acmeclient.Authorization, error) {
	c.authzSeen = authzURL
	return c.authz, nil
}

func (c *fakeACMEClient) InitiateChallenge(ctx context.Context, account acmeclient.Account, challenge acmeclient.Challenge) (acmeclient.Challenge, error) {
	c.challengeSeen = challenge
	return challenge, nil
}

func (c *fakeACMEClient) PollAuthorization(ctx context.Context, account acmeclient.Account, authz acmeclient.Authorization) (acmeclient.Authorization, error) {
	return authz, nil
}

func (c *fakeACMEClient) GetOrder(ctx context.Context, account acmeclient.Account, order acmeclient.Order) (acmeclient.Order, error) {
	return c.finalized, nil
}

func (c *fakeACMEClient) FinalizeOrder(ctx context.Context, account acmeclient.Account, order acmeclient.Order, csrASN1DER []byte) (acmeclient.Order, error) {
	return c.finalized, nil
}

func (c *fakeACMEClient) GetCertificateChain(ctx context.Context, account acmeclient.Account, certURL string) ([]acmeclient.Certificate, error) {
	return c.certs, nil
}

func TestStartOrderPersistsDomainID(t *testing.T) {
	orderRepo := &fakeOrderRepo{}
	challengeRepo := &fakeChallengeRepo{}
	accountRepo := &fakeAccountRepo{}
	prov := NewProvider("https://acme.test/directory", "ops@example.com", orderRepo, challengeRepo, accountRepo, zap.NewNop())
	prov.client = &fakeACMEClient{
		order: acmeclient.Order{
			Location: "https://acme.test/order/1",
			Authorizations: []string{
				"https://acme.test/authz/1",
			},
		},
		authz: acmeclient.Authorization{
			Location: "https://acme.test/authz/1",
			Challenges: []acmeclient.Challenge{
				{Type: "dns-01", URL: "https://acme.test/challenge/1", Token: "token-1", KeyAuthorization: "token-1.thumb"},
			},
		},
	}

	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	order, challenge, err := prov.StartOrder(context.Background(), "domain-123", "example.com", accountKey, "kid-123")
	if err != nil {
		t.Fatalf("StartOrder() error = %v", err)
	}

	if got := order.DomainID; got != "domain-123" {
		t.Fatalf("order DomainID = %q, want %q", got, "domain-123")
	}
	if got := challenge.DomainID; got != "domain-123" {
		t.Fatalf("challenge DomainID = %q, want %q", got, "domain-123")
	}
	if got := orderRepo.created[len(orderRepo.created)-1].DomainID; got != "domain-123" {
		t.Fatalf("persisted order DomainID = %q, want %q", got, "domain-123")
	}
	if got := challengeRepo.created[len(challengeRepo.created)-1].DomainID; got != "domain-123" {
		t.Fatalf("persisted challenge DomainID = %q, want %q", got, "domain-123")
	}
}

func TestCompleteOrderReturnsCertificateData(t *testing.T) {
	orderRepo := &fakeOrderRepo{}
	challengeRepo := &fakeChallengeRepo{}
	accountRepo := &fakeAccountRepo{}
	prov := NewProvider("https://acme.test/directory", "ops@example.com", orderRepo, challengeRepo, accountRepo, zap.NewNop())
	prov.client = &fakeACMEClient{
		finalized: acmeclient.Order{
			Status:      "valid",
			Certificate: "https://acme.test/cert/1",
			Identifiers: []acmeclient.Identifier{{Type: "dns", Value: "example.com"}},
		},
		certs: []acmeclient.Certificate{
			{ChainPEM: []byte("CERT")},
		},
	}

	orderRepo.created = append(orderRepo.created, &Order{
		ID:       "order-1",
		DomainID: "domain-123",
		OrderURL: "https://acme.test/order/1",
		Status:   "pending",
	})
	challengeRepo.created = append(challengeRepo.created, &Challenge{
		ID:               "challenge-1",
		DomainID:         "domain-123",
		AuthorizationURL: "https://acme.test/authz/1",
		ChallengeURL:     "https://acme.test/challenge/1",
		Token:            "token-1",
		KeyAuthorization: "token-1.thumb",
		TXTValue:         "txt-1",
		Status:           "pending",
	})

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	certPEM, keyPEM, issuedAt, expiresAt, err := prov.CompleteOrder(context.Background(), key, "kid-123", "order-1", *challengeRepo.created[0])
	if err != nil {
		t.Fatalf("CompleteOrder() error = %v", err)
	}

	if certPEM != "CERT" {
		t.Fatalf("certPEM = %q, want %q", certPEM, "CERT")
	}
	if keyPEM == "" {
		t.Fatal("expected private key PEM")
	}
	if issuedAt.IsZero() || expiresAt.IsZero() {
		t.Fatal("expected timestamps to be set")
	}
	if !expiresAt.After(issuedAt) {
		t.Fatal("expected expiresAt after issuedAt")
	}
}
