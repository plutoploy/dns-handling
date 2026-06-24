package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/mholt/acmez/v3/acme"
)

type Account struct {
	KID           string
	PrivateKeyPEM string
}

type Order struct {
	ID        string     `json:"id"`
	DomainID  string     `json:"domain_id"`
	OrderURL  string     `json:"order_url"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type Challenge struct {
	ID               string    `json:"id"`
	DomainID         string    `json:"domain_id"`
	AuthorizationURL string    `json:"authorization_url"`
	ChallengeURL     string    `json:"challenge_url"`
	Token            string    `json:"token"`
	KeyAuthorization string    `json:"key_authorization"`
	TXTValue         string    `json:"txt_value"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
}

type OrderRepository interface {
	Create(ctx context.Context, o *Order) error
	GetByDomainID(ctx context.Context, domainID string) (*Order, error)
	GetByID(ctx context.Context, id string) (*Order, error)
	Update(ctx context.Context, o *Order) error
}

type ChallengeRepository interface {
	Create(ctx context.Context, c *Challenge) error
	GetByDomainID(ctx context.Context, domainID string) (*Challenge, error)
	Update(ctx context.Context, c *Challenge) error
}

type AccountRepository interface {
	Get(ctx context.Context) (*Account, error)
	Save(ctx context.Context, a *Account) error
}

type client interface {
	NewAccount(ctx context.Context, account acme.Account) (acme.Account, error)
	NewOrder(ctx context.Context, account acme.Account, order acme.Order) (acme.Order, error)
	GetAuthorization(ctx context.Context, account acme.Account, authzURL string) (acme.Authorization, error)
	InitiateChallenge(ctx context.Context, account acme.Account, challenge acme.Challenge) (acme.Challenge, error)
	PollAuthorization(ctx context.Context, account acme.Account, authz acme.Authorization) (acme.Authorization, error)
	GetOrder(ctx context.Context, account acme.Account, order acme.Order) (acme.Order, error)
	FinalizeOrder(ctx context.Context, account acme.Account, order acme.Order, csrASN1DER []byte) (acme.Order, error)
	GetCertificateChain(ctx context.Context, account acme.Account, certURL string) ([]acme.Certificate, error)
}

type Provider interface {
	SetupAccount(ctx context.Context) (crypto.Signer, string, error)
	StartOrder(ctx context.Context, domainID, domainName string, accountKey crypto.Signer, accountKID string) (*Order, *Challenge, error)
	CompleteOrder(ctx context.Context, accountKey crypto.Signer, accountKID, orderID string, ch Challenge) (string, string, time.Time, time.Time, error)
}

type ACMEProvider struct {
	client       client
	email        string
	orderRepo    OrderRepository
	challengeRep ChallengeRepository
	accountRepo  AccountRepository
	logger       *zap.Logger
}

func NewProvider(
	directory, email string,
	orderRepo OrderRepository,
	challengeRepo ChallengeRepository,
	accountRepo AccountRepository,
	logger *zap.Logger,
) *ACMEProvider {
	return &ACMEProvider{
		client: &acme.Client{
			Directory: directory,
		},
		email:        email,
		orderRepo:    orderRepo,
		challengeRep: challengeRepo,
		accountRepo:  accountRepo,
		logger:       logger,
	}
}

func (p *ACMEProvider) SetupAccount(ctx context.Context) (crypto.Signer, string, error) {
	existing, err := p.accountRepo.Get(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("get existing account: %w", err)
	}
	if existing != nil {
		key, err := pemToSigner(existing.PrivateKeyPEM)
		if err != nil {
			return nil, "", fmt.Errorf("parse existing account key: %w", err)
		}
		return key, existing.KID, nil
	}

	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("generate account key: %w", err)
	}

	acct := acme.Account{
		Contact:              []string{"mailto:" + p.email},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountKey,
	}

	createdAcct, err := p.client.NewAccount(ctx, acct)
	if err != nil {
		return nil, "", fmt.Errorf("create ACME account: %w", err)
	}

	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(accountKey),
	}))

	acc := &Account{
		KID:           createdAcct.Location,
		PrivateKeyPEM: keyPEM,
	}

	if err := p.accountRepo.Save(ctx, acc); err != nil {
		return nil, "", fmt.Errorf("save account: %w", err)
	}

	p.logger.Info("created ACME account", zap.String("kid", acc.KID))
	return accountKey, acc.KID, nil
}

func (p *ACMEProvider) StartOrder(
	ctx context.Context,
	domainID,
	domainName string,
	accountKey crypto.Signer,
	accountKID string,
) (*Order, *Challenge, error) {
	acct := acme.Account{
		Location:   accountKID,
		PrivateKey: accountKey,
	}

	acmeOrder, err := p.client.NewOrder(ctx, acct, acme.Order{
		Identifiers: []acme.Identifier{
			{Type: "dns", Value: domainName},
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create ACME order: %w", err)
	}

	authz, err := p.client.GetAuthorization(ctx, acct, acmeOrder.Authorizations[0])
	if err != nil {
		return nil, nil, fmt.Errorf("get authorization: %w", err)
	}

	var dnsChallenge acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			dnsChallenge = ch
			break
		}
	}

	if dnsChallenge.Type == "" {
		return nil, nil, fmt.Errorf("no dns-01 challenge available for %s", domainName)
	}

	txtValue := dnsChallenge.DNS01KeyAuthorization()

	order := &Order{
		ID:        newID(),
		DomainID:  domainID,
		OrderURL:  acmeOrder.Location,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}

	if err := p.orderRepo.Create(ctx, order); err != nil {
		return nil, nil, fmt.Errorf("save order: %w", err)
	}

	challenge := &Challenge{
		ID:               newID(),
		DomainID:         domainID,
		AuthorizationURL: authz.Location,
		ChallengeURL:     dnsChallenge.URL,
		Token:            dnsChallenge.Token,
		KeyAuthorization: dnsChallenge.KeyAuthorization,
		TXTValue:         txtValue,
		Status:           "pending",
		CreatedAt:        time.Now().UTC(),
	}

	if err := p.challengeRep.Create(ctx, challenge); err != nil {
		return nil, nil, fmt.Errorf("save challenge: %w", err)
	}

	return order, challenge, nil
}

func (p *ACMEProvider) CompleteOrder(
	ctx context.Context,
	accountKey crypto.Signer,
	accountKID, orderID string,
	ch Challenge,
) (string, string, time.Time, time.Time, error) {
	acct := acme.Account{
		Location:   accountKID,
		PrivateKey: accountKey,
	}

	orderRec, err := p.orderRepo.GetByID(ctx, orderID)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("get order: %w", err)
	}

	acmeOrder := acme.Order{Location: orderRec.OrderURL}
	acmeOrder, err = p.client.GetOrder(ctx, acct, acmeOrder)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("get order details: %w", err)
	}

	dnsChallenge := acme.Challenge{
		URL:   ch.ChallengeURL,
		Token: ch.Token,
	}

	dnsChallenge, err = p.client.InitiateChallenge(ctx, acct, dnsChallenge)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("initiate challenge: %w", err)
	}

	ch.Status = "processing"
	_ = p.challengeRep.Update(ctx, &ch)

	p.logger.Info("waiting for ACME challenge validation", zap.String("order", orderID))

	authzURL := ch.AuthorizationURL
	_, err = p.client.PollAuthorization(ctx, acct, acme.Authorization{Location: authzURL})
	if err != nil {
		orderRec.Status = "failed"
		_ = p.orderRepo.Update(ctx, orderRec)
		ch.Status = "failed"
		_ = p.challengeRep.Update(ctx, &ch)
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("challenge validation failed: %w", err)
	}

	ch.Status = "valid"
	_ = p.challengeRep.Update(ctx, &ch)

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("generate cert key: %w", err)
	}

	if len(acmeOrder.Identifiers) == 0 {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("order missing identifiers")
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{acmeOrder.Identifiers[0].Value},
	}, certKey)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("create CSR: %w", err)
	}

	acmeOrder, err = p.client.FinalizeOrder(ctx, acct, acmeOrder, csr)
	if err != nil {
		orderRec.Status = "failed"
		_ = p.orderRepo.Update(ctx, orderRec)
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("finalize order: %w", err)
	}

	if acmeOrder.Status != "valid" {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("order finalized with unexpected status: %s", acmeOrder.Status)
	}

	certChains, err := p.client.GetCertificateChain(ctx, acct, acmeOrder.Certificate)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("get certificate: %w", err)
	}

	if len(certChains) == 0 {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("no certificate chains returned")
	}

	certPEM := string(certChains[0].ChainPEM)

	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	}))

	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(90 * 24 * time.Hour)

	orderRec.Status = "valid"
	_ = p.orderRepo.Update(ctx, orderRec)

	return certPEM, keyPEM, issuedAt, expiresAt, nil
}

func pemToSigner(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
