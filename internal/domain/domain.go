package domain

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type Status string

const (
	StatusPending            Status = "pending"
	StatusVerified           Status = "verified"
	StatusCertificatePending Status = "certificate_pending"
	StatusActive             Status = "active"
	StatusFailed             Status = "failed"
)

type Domain struct {
	ID                string    `json:"id"`
	DomainName        string    `json:"domain_name"`
	VerificationToken string    `json:"verification_token"`
	Status            Status    `json:"status"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Repository interface {
	Create(ctx context.Context, d *Domain) error
	GetByID(ctx context.Context, id string) (*Domain, error)
	GetByDomainName(ctx context.Context, name string) (*Domain, error)
	Update(ctx context.Context, d *Domain) error
}

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (s *Service) Create(ctx context.Context, domainName string) (*Domain, error) {
	token, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	d := &Domain{
		ID:                newID(),
		DomainName:        domainName,
		VerificationToken: token,
		Status:            StatusPending,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	if err := s.repo.Create(ctx, d); err != nil {
		return nil, fmt.Errorf("create domain: %w", err)
	}

	return d, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*Domain, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *Service) VerifyTXT(ctx context.Context, id string, txtRecords []string) (*Domain, error) {
	d, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	if d.Status != StatusPending {
		return nil, fmt.Errorf("domain %s is in status %s, expected pending", d.DomainName, d.Status)
	}

	if !contains(txtRecords, d.VerificationToken) {
		return nil, fmt.Errorf("verification token not found in TXT records")
	}

	now := time.Now().UTC()
	d.Status = StatusVerified
	d.VerifiedAt = &now
	d.UpdatedAt = now

	if err := s.repo.Update(ctx, d); err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}

	return d, nil
}

func (s *Service) SetCertificatePending(ctx context.Context, id string) (*Domain, error) {
	d, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	if d.Status != StatusVerified {
		return nil, fmt.Errorf("domain %s is in status %s, expected verified", d.DomainName, d.Status)
	}

	d.Status = StatusCertificatePending
	d.UpdatedAt = time.Now().UTC()

	if err := s.repo.Update(ctx, d); err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}

	return d, nil
}

func (s *Service) SetActive(ctx context.Context, id string) (*Domain, error) {
	d, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	d.Status = StatusActive
	d.UpdatedAt = time.Now().UTC()

	if err := s.repo.Update(ctx, d); err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}

	return d, nil
}

func (s *Service) SetFailed(ctx context.Context, id string) (*Domain, error) {
	d, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	d.Status = StatusFailed
	d.UpdatedAt = time.Now().UTC()

	if err := s.repo.Update(ctx, d); err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}

	return d, nil
}

func (s *Service) ChallengeDomain(domainName string) string {
	return fmt.Sprintf("_acme-challenge.%s.", domainName)
}

func contains(records []string, target string) bool {
	for _, r := range records {
		if r == target {
			return true
		}
	}
	return false
}

var newID = func() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
