package database

import (
	"context"
	"database/sql"
	"fmt"

	"plutoploy/tls/internal/domain"
)

type DomainRepository struct {
	db *DB
}

func NewDomainRepository(db *DB) *DomainRepository {
	return &DomainRepository{db: db}
}

func (r *DomainRepository) Create(ctx context.Context, d *domain.Domain) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO domains (id, domain_name, verification_token, project_subdomain, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.DomainName, d.VerificationToken, d.ProjectSubdomain, d.Status, d.CreatedAt, d.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert domain: %w", err)
	}
	return nil
}

func (r *DomainRepository) GetByID(ctx context.Context, id string) (*domain.Domain, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, domain_name, verification_token, COALESCE(project_subdomain, ''), status, verified_at, created_at, updated_at
		 FROM domains WHERE id = ?`, id,
	)

	return scanDomain(row)
}

func (r *DomainRepository) GetByDomainName(ctx context.Context, name string) (*domain.Domain, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, domain_name, verification_token, COALESCE(project_subdomain, ''), status, verified_at, created_at, updated_at
		 FROM domains WHERE domain_name = ?`, name,
	)

	return scanDomain(row)
}

func (r *DomainRepository) ListByStatus(ctx context.Context, status domain.Status) ([]*domain.Domain, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, domain_name, verification_token, COALESCE(project_subdomain, ''), status, verified_at, created_at, updated_at
		 FROM domains WHERE status = ? ORDER BY created_at ASC`, status,
	)
	if err != nil {
		return nil, fmt.Errorf("list domains by status: %w", err)
	}
	defer rows.Close()

	var out []*domain.Domain
	for rows.Next() {
		var d domain.Domain
		var verifiedAt sql.NullTime
		if err := rows.Scan(&d.ID, &d.DomainName, &d.VerificationToken, &d.ProjectSubdomain, &d.Status, &verifiedAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		if verifiedAt.Valid {
			d.VerifiedAt = &verifiedAt.Time
		}
		out = append(out, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate domains: %w", err)
	}
	return out, nil
}

func (r *DomainRepository) Update(ctx context.Context, d *domain.Domain) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE domains SET status = ?, verified_at = ?, updated_at = ? WHERE id = ?`,
		d.Status, d.VerifiedAt, d.UpdatedAt, d.ID,
	)
	if err != nil {
		return fmt.Errorf("update domain: %w", err)
	}
	return nil
}

func scanDomain(row *sql.Row) (*domain.Domain, error) {
	var d domain.Domain
	var verifiedAt sql.NullTime

	err := row.Scan(&d.ID, &d.DomainName, &d.VerificationToken, &d.ProjectSubdomain, &d.Status, &verifiedAt, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("domain not found")
		}
		return nil, fmt.Errorf("scan domain: %w", err)
	}

	if verifiedAt.Valid {
		d.VerifiedAt = &verifiedAt.Time
	}

	return &d, nil
}
