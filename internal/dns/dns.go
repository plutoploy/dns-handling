package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type Resolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

type NetResolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

func NewNetResolver(timeout time.Duration) *NetResolver {
	return &NetResolver{
		resolver: net.DefaultResolver,
		timeout:  timeout,
	}
}

func (r *NetResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	records, err := r.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("lookup TXT %s: %w", domain, err)
	}

	var filtered []string
	for _, rec := range records {
		filtered = append(filtered, strings.Trim(rec, `"`))
	}
	return filtered, nil
}
