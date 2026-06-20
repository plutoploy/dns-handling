package database

import (
	"context"
	"database/sql"
	"fmt"

	"plutoploy/tls/internal/acme"
)

type ACMEAccountRepository struct {
	db *DB
}

func NewACMEAccountRepository(db *DB) *ACMEAccountRepository {
	return &ACMEAccountRepository{db: db}
}

func (r *ACMEAccountRepository) Get(ctx context.Context) (*acme.Account, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT kid, private_key_pem FROM acme_accounts LIMIT 1`,
	)

	var kid, keyPEM string
	err := row.Scan(&kid, &keyPEM)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan acme account: %w", err)
	}

	return &acme.Account{KID: kid, PrivateKeyPEM: keyPEM}, nil
}

func (r *ACMEAccountRepository) Save(ctx context.Context, a *acme.Account) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO acme_accounts (kid, private_key_pem) VALUES (?, ?)`,
		a.KID, a.PrivateKeyPEM,
	)
	if err != nil {
		return fmt.Errorf("insert acme account: %w", err)
	}
	return nil
}
