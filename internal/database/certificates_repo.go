package database

import (
	"context"
	"database/sql"
	"fmt"

	"plutoploy/tls/internal/certificates"
)

type CertificateRepository struct {
	db *DB
}

func NewCertificateRepository(db *DB) *CertificateRepository {
	return &CertificateRepository{db: db}
}

func (r *CertificateRepository) Create(ctx context.Context, c *certificates.Certificate) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO certificates (id, domain_id, certificate_pem, private_key_pem, issued_at, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.DomainID, c.CertificatePEM, c.PrivateKeyPEM, c.IssuedAt, c.ExpiresAt, c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert certificate: %w", err)
	}
	return nil
}

func (r *CertificateRepository) GetByDomainID(ctx context.Context, domainID string) (*certificates.Certificate, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, domain_id, certificate_pem, private_key_pem, issued_at, expires_at, created_at
		 FROM certificates WHERE domain_id = ? ORDER BY created_at DESC LIMIT 1`, domainID,
	)

	return scanCertificate(row)
}

func (r *CertificateRepository) GetByID(ctx context.Context, id string) (*certificates.Certificate, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, domain_id, certificate_pem, private_key_pem, issued_at, expires_at, created_at
		 FROM certificates WHERE id = ?`, id,
	)

	return scanCertificate(row)
}

func scanCertificate(row *sql.Row) (*certificates.Certificate, error) {
	var c certificates.Certificate
	err := row.Scan(&c.ID, &c.DomainID, &c.CertificatePEM, &c.PrivateKeyPEM, &c.IssuedAt, &c.ExpiresAt, &c.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("scan certificate: %w", err)
	}
	return &c, nil
}
