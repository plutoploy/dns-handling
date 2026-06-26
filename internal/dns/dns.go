package dns

import (
	"context"
	"net"
	"strings"
)

// Resolver defines the interface for DNS client resolution.
type Resolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// NetResolver is a simple DNS client using Go's default resolver.
type NetResolver struct{}

// LookupTXT queries TXT records for a domain.
func (r *NetResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}
	for i, rec := range records {
		records[i] = strings.Trim(rec, `"`)
	}
	return records, nil
}
