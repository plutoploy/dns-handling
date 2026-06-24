package dns

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type DynamicResolver struct {
	baseDomain string
	ipCache    string
	cacheMu    sync.RWMutex
	cacheTime  time.Time
	cacheTTL   time.Duration
	client     *http.Client
	logger     *zap.Logger
}

func NewDynamicResolver(baseDomain string, cacheTTL time.Duration, logger *zap.Logger) *DynamicResolver {
	return &DynamicResolver{
		baseDomain: baseDomain,
		cacheTTL:   cacheTTL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

func (r *DynamicResolver) GetPublicIP(ctx context.Context) (string, error) {
	r.cacheMu.RLock()
	if r.ipCache != "" && time.Since(r.cacheTime) < r.cacheTTL {
		defer r.cacheMu.RUnlock()
		return r.ipCache, nil
	}
	r.cacheMu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ifconfig.me/ip", nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("get public IP: %w", err)
	}
	defer resp.Body.Close()

	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	ipStr := strings.TrimSpace(string(ipBytes))
	if net.ParseIP(ipStr) == nil {
		return "", fmt.Errorf("invalid IP: %s", ipStr)
	}

	r.cacheMu.Lock()
	r.ipCache = ipStr
	r.cacheTime = time.Now()
	r.cacheMu.Unlock()

	return ipStr, nil
}

func (r *DynamicResolver) IPToSubdomain(ip string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP: %s", ip)
	}

	if v4 := parsedIP.To4(); v4 != nil {
		hexStr := fmt.Sprintf("%02x%02x%02x%02x", v4[0], v4[1], v4[2], v4[3])
		return hexStr + "." + r.baseDomain, nil
	}

	hexStr := hex.EncodeToString(parsedIP.To16())
	return hexStr + "." + r.baseDomain, nil
}

func (r *DynamicResolver) GetDynamicDomain(ctx context.Context) (string, error) {
	ip, err := r.GetPublicIP(ctx)
	if err != nil {
		return "", err
	}
	return r.IPToSubdomain(ip)
}

func (r *DynamicResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	records, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("lookup TXT %s: %w", domain, err)
	}

	var filtered []string
	for _, rec := range records {
		filtered = append(filtered, strings.Trim(rec, `"`))
	}
	return filtered, nil
}
