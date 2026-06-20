package certificates

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type Certificate struct {
	ID             string    `json:"id"`
	DomainID       string    `json:"domain_id"`
	CertificatePEM string    `json:"certificate_pem"`
	PrivateKeyPEM  string    `json:"private_key_pem"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
}

type Repository interface {
	Create(ctx context.Context, c *Certificate) error
	GetByDomainID(ctx context.Context, domainID string) (*Certificate, error)
	GetByID(ctx context.Context, id string) (*Certificate, error)
}

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Store(ctx context.Context, domainID, certPEM, keyPEM string, issuedAt, expiresAt time.Time) (*Certificate, error) {
	c := &Certificate{
		ID:             newID(),
		DomainID:       domainID,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
		CreatedAt:      time.Now().UTC(),
	}

	if err := s.repo.Create(ctx, c); err != nil {
		return nil, fmt.Errorf("store certificate: %w", err)
	}

	return c, nil
}

func (s *Service) GetByDomainID(ctx context.Context, domainID string) (*Certificate, error) {
	return s.repo.GetByDomainID(ctx, domainID)
}

func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func EncodePrivateKey(key *rsa.PrivateKey) string {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

func EncodeCertificate(der []byte) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block))
}

func GenerateSelfSignedCert(key *rsa.PrivateKey, domain string) ([]byte, time.Time, time.Time, error) {
	now := time.Now()
	issuedAt := now
	expiresAt := now.Add(365 * 24 * time.Hour)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    issuedAt,
		NotAfter:     expiresAt,
		DNSNames:     []string{domain},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("create certificate: %w", err)
	}

	return der, issuedAt, expiresAt, nil
}

var newID = func() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
