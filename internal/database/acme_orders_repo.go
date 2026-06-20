package database

import (
	"context"
	"database/sql"
	"fmt"

	"plutoploy/tls/internal/acme"
)

type ACMEOrderRepository struct {
	db *DB
}

func NewACMEOrderRepository(db *DB) *ACMEOrderRepository {
	return &ACMEOrderRepository{db: db}
}

func (r *ACMEOrderRepository) Create(ctx context.Context, o *acme.Order) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO acme_orders (id, domain_id, order_url, status, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		o.ID, o.DomainID, o.OrderURL, o.Status, o.ExpiresAt, o.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert acme order: %w", err)
	}
	return nil
}

func (r *ACMEOrderRepository) GetByDomainID(ctx context.Context, domainID string) (*acme.Order, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, domain_id, order_url, status, expires_at, created_at
		 FROM acme_orders WHERE domain_id = ? ORDER BY created_at DESC LIMIT 1`, domainID,
	)

	return scanOrder(row)
}

func (r *ACMEOrderRepository) Update(ctx context.Context, o *acme.Order) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = ?, expires_at = ? WHERE id = ?`,
		o.Status, o.ExpiresAt, o.ID,
	)
	if err != nil {
		return fmt.Errorf("update acme order: %w", err)
	}
	return nil
}

func scanOrder(row *sql.Row) (*acme.Order, error) {
	var o acme.Order
	var expiresAt sql.NullTime

	err := row.Scan(&o.ID, &o.DomainID, &o.OrderURL, &o.Status, &expiresAt, &o.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("order not found")
		}
		return nil, fmt.Errorf("scan acme order: %w", err)
	}

	if expiresAt.Valid {
		o.ExpiresAt = &expiresAt.Time
	}

	return &o, nil
}

func (r *ACMEOrderRepository) GetByID(ctx context.Context, id string) (*acme.Order, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, domain_id, order_url, status, expires_at, created_at
		 FROM acme_orders WHERE id = ?`, id,
	)

	return scanOrder(row)
}
