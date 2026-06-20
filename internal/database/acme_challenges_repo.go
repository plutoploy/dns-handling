package database

import (
	"context"
	"database/sql"
	"fmt"

	"plutoploy/tls/internal/acme"
)

type ACMEChallengeRepository struct {
	db *DB
}

func NewACMEChallengeRepository(db *DB) *ACMEChallengeRepository {
	return &ACMEChallengeRepository{db: db}
}

func (r *ACMEChallengeRepository) Create(ctx context.Context, c *acme.Challenge) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO acme_challenges (id, domain_id, authorization_url, challenge_url, token, key_authorization, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.DomainID, c.AuthorizationURL, c.ChallengeURL, c.Token, c.KeyAuthorization, c.Status, c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert acme challenge: %w", err)
	}
	return nil
}

func (r *ACMEChallengeRepository) GetByDomainID(ctx context.Context, domainID string) (*acme.Challenge, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, domain_id, authorization_url, challenge_url, token, key_authorization, status, created_at
		 FROM acme_challenges WHERE domain_id = ? ORDER BY created_at DESC LIMIT 1`, domainID,
	)

	return scanChallenge(row)
}

func (r *ACMEChallengeRepository) Update(ctx context.Context, c *acme.Challenge) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE acme_challenges SET status = ? WHERE id = ?`,
		c.Status, c.ID,
	)
	if err != nil {
		return fmt.Errorf("update acme challenge: %w", err)
	}
	return nil
}

func scanChallenge(row *sql.Row) (*acme.Challenge, error) {
	var c acme.Challenge
	err := row.Scan(&c.ID, &c.DomainID, &c.AuthorizationURL, &c.ChallengeURL, &c.Token, &c.KeyAuthorization, &c.Status, &c.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("challenge not found")
		}
		return nil, fmt.Errorf("scan challenge: %w", err)
	}
	return &c, nil
}
