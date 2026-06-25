package dns

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"github.com/miekg/dns"

	"plutoploy/tls/internal/database"
	"plutoploy/tls/internal/domain"
	"plutoploy/tls/internal/acme"
)

func TestIPToSubdomain(t *testing.T) {
	logger := zaptest.NewLogger(t)
	r := NewDynamicResolver("example.com", time.Minute, logger)

	tests := []struct {
		ip      string
		want    string
		wantErr bool
	}{
		{
			ip:   "127.0.0.1",
			want: "dns-7f000001.example.com",
		},
		{
			ip:   "8.8.8.8",
			want: "dns-08080808.example.com",
		},
		{
			ip:      "invalid-ip",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got, err := r.IPToSubdomain(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IPToSubdomain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("IPToSubdomain() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDNSServerResolution(t *testing.T) {
	logger := zaptest.NewLogger(t)
	r := NewDynamicResolver("example.com", time.Minute, logger)

	s := NewDNSServer(DNSServerConfig{
		BaseDomain: "example.com",
		Resolver:   r,
		Logger:     logger,
	})

	tests := []struct {
		subdomain string
		wantIP    net.IP
		wantErr   bool
	}{
		{
			subdomain: "dns.7f000001",
			wantIP:    net.IPv4(127, 0, 0, 1),
		},
		{
			subdomain: "7f000001",
			wantIP:    net.IPv4(127, 0, 0, 1),
		},
		{
			subdomain: "dns.08080808",
			wantIP:    net.IPv4(8, 8, 8, 8),
		},
		{
			subdomain: "invalid",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.subdomain, func(t *testing.T) {
			got, err := s.decodeSubdomainToIP(tt.subdomain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeSubdomainToIP() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if !got.Equal(tt.wantIP) {
					t.Errorf("decodeSubdomainToIP() = %v, want %v", got, tt.wantIP)
				}
			}
		})
	}
}

func TestDNSServerResolveA(t *testing.T) {
	logger := zaptest.NewLogger(t)
	r := NewDynamicResolver("example.com", time.Minute, logger)

	s := NewDNSServer(DNSServerConfig{
		BaseDomain: "example.com",
		Resolver:   r,
		Logger:     logger,
	})

	// Test resolving A record with dns. prefix
	ips := s.resolveA("dns.7f000001.example.com.")
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("got %v, want 127.0.0.1", ips[0])
	}

	// Test resolving A record without dns. prefix (backward compatibility)
	ips2 := s.resolveA("7f000001.example.com.")
	if len(ips2) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips2))
	}
	if !ips2[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("got %v, want 127.0.0.1", ips2[0])
	}

	// Test resolving A record with project prefix: p0.7f000001.example.com.
	ips3 := s.resolveA("p0.7f000001.example.com.")
	if len(ips3) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips3))
	}
	if !ips3[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("got %v, want 127.0.0.1", ips3[0])
	}

	// Test resolving A record with double project prefix: sub.p0.7f000001.example.com.
	ips4 := s.resolveA("sub.p0.7f000001.example.com.")
	if len(ips4) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips4))
	}
	if !ips4[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("got %v, want 127.0.0.1", ips4[0])
	}

	// Test resolving A record with hyphen project prefix: p0-7f000001.example.com.
	ips5 := s.resolveA("p0-7f000001.example.com.")
	if len(ips5) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips5))
	}
	if !ips5[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("got %v, want 127.0.0.1", ips5[0])
	}

	// Test resolving A record with project prefix + hyphen: sub.p0-7f000001.example.com.
	ips6 := s.resolveA("sub.p0-7f000001.example.com.")
	if len(ips6) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips6))
	}
	if !ips6[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("got %v, want 127.0.0.1", ips6[0])
	}

	// Test resolving A record with specific project1-7f000001.example.com. structure
	ips7 := s.resolveA("project1-7f000001.example.com.")
	if len(ips7) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips7))
	}
	if !ips7[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("got %v, want 127.0.0.1", ips7[0])
	}
}

func TestDNSServerForwarding(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Start a dummy upstream DNS server
	upstreamMux := dns.NewServeMux()
	upstreamMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA && q.Name == "external.domain." {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.IPv4(9, 9, 9, 9),
				}
				msg.Answer = append(msg.Answer, rr)
			}
		}
		w.WriteMsg(msg)
	})

	upstreamServer := &dns.Server{
		Addr:    "127.0.0.1:0", // Bind to any free port
		Net:     "udp",
		Handler: upstreamMux,
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	upstreamServer.PacketConn = pc
	defer pc.Close()

	go func() {
		if err := upstreamServer.ActivateAndServe(); err != nil {
			logger.Error("upstream server err", zap.Error(err))
		}
	}()
	defer upstreamServer.Shutdown()

	upstreamAddr := pc.LocalAddr().String()

	// Start our recursive local resolver pointing to upstream
	r := NewDynamicResolver("example.com", time.Minute, logger)
	s := NewDNSServer(DNSServerConfig{
		BaseDomain: "example.com",
		Resolver:   r,
		Logger:     logger,
		Upstreams:  []string{upstreamAddr},
		ListenAddr: "127.0.0.1:0",
	})

	localPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen local packet: %v", err)
	}
	s.server.PacketConn = localPC
	defer localPC.Close()

	go func() {
		if err := s.server.ActivateAndServe(); err != nil {
			logger.Error("local server err", zap.Error(err))
		}
	}()
	defer s.Shutdown()

	localAddr := localPC.LocalAddr().String()

	// Query our local resolver for "external.domain"
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = time.Second

	msg := new(dns.Msg)
	msg.SetQuestion("external.domain.", dns.TypeA)

	resp, _, err := c.Exchange(msg, localAddr)
	if err != nil {
		t.Fatalf("dns exchange error = %v", err)
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}

	if aRecord, ok := resp.Answer[0].(*dns.A); ok {
		if !aRecord.A.Equal(net.IPv4(9, 9, 9, 9)) {
			t.Errorf("got IP %v, want 9.9.9.9", aRecord.A)
		}
	} else {
		t.Errorf("expected A record, got %T", resp.Answer[0])
	}
}

func TestDNSServerResolveTXTDynamically(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create test DB
	db, err := database.New("file::memory:?cache=shared", logger)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Insert pending domain verification
	domainRepo := database.NewDomainRepository(db)
	d := &domain.Domain{
		ID:                "domain-1",
		DomainName:        "app.userdomain.com",
		VerificationToken: "verification-token-abc",
		Status:            domain.StatusPending,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	if err := domainRepo.Create(context.Background(), d); err != nil {
		t.Fatalf("failed to create domain: %v", err)
	}

	// Insert pending ACME challenge
	challengeRepo := database.NewACMEChallengeRepository(db)
	ch := &acme.Challenge{
		ID:               "challenge-1",
		DomainID:         "domain-1",
		AuthorizationURL: "https://authz",
		ChallengeURL:     "https://challenge",
		Token:            "acme-token",
		KeyAuthorization: "key-auth-xyz",
		Status:           "pending",
		CreatedAt:        time.Now().UTC(),
	}
	if err := challengeRepo.Create(context.Background(), ch); err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}

	// Start resolver
	r := NewDynamicResolver("example.com", time.Minute, logger)
	s := NewDNSServer(DNSServerConfig{
		BaseDomain: "example.com",
		Resolver:   r,
		Logger:     logger,
		DB:         db,
		ListenAddr: "127.0.0.1:0",
	})

	localPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen local packet: %v", err)
	}
	s.server.PacketConn = localPC
	defer localPC.Close()

	go func() {
		if err := s.server.ActivateAndServe(); err != nil {
			logger.Error("local server err", zap.Error(err))
		}
	}()
	defer s.Shutdown()

	localAddr := localPC.LocalAddr().String()

	origResolver := net.DefaultResolver
	defer func() {
		net.DefaultResolver = origResolver
	}()

	mockMux := dns.NewServeMux()
	mockMux.HandleFunc("app.userdomain.com.", func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true
		for _, q := range req.Question {
			if q.Qtype == dns.TypeA {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.IPv4(127, 0, 0, 1),
				}
				msg.Answer = append(msg.Answer, rr)
			}
		}
		w.WriteMsg(msg)
	})
	mockMux.HandleFunc("_acme-challenge.app.userdomain.com.", func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true
		for _, q := range req.Question {
			if q.Qtype == dns.TypeCNAME {
				rr := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Target: "_acme-challenge.project1-7f000001.example.com.",
				}
				msg.Answer = append(msg.Answer, rr)
			}
		}
		w.WriteMsg(msg)
	})

	mockServer := &dns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "udp",
		Handler: mockMux,
	}
	mockPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock packet: %v", err)
	}
	mockServer.PacketConn = mockPC
	defer mockPC.Close()

	go func() {
		_ = mockServer.ActivateAndServe()
	}()
	defer mockServer.Shutdown()

	mockAddr := mockPC.LocalAddr().String()

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", mockAddr)
		},
	}
	s.refreshPendingTXTCacheOnce(context.Background())

	// Query our local DNSServer for TXT record of _acme-challenge.project1-7f000001.example.com.
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = time.Second

	msg := new(dns.Msg)
	msg.SetQuestion("_acme-challenge.project1-7f000001.example.com.", dns.TypeTXT)
	resp, _, err := c.Exchange(msg, localAddr)
	if err != nil {
		t.Fatalf("TXT verification query error: %v", err)
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer for verification TXT, got %d", len(resp.Answer))
	}
	if txtRecord, ok := resp.Answer[0].(*dns.TXT); ok {
		if len(txtRecord.Txt) != 1 || txtRecord.Txt[0] != "verification-token-abc" {
			t.Errorf("got TXT %v, want [verification-token-abc]", txtRecord.Txt)
		}
	} else {
		t.Errorf("expected TXT record, got %T", resp.Answer[0])
	}

	d.Status = domain.StatusVerified
	if err := domainRepo.Update(context.Background(), d); err != nil {
		t.Fatalf("failed to update domain to verified: %v", err)
	}
	s.refreshPendingTXTCacheOnce(context.Background())

	resp2, _, err := c.Exchange(msg, localAddr)
	if err != nil {
		t.Fatalf("TXT ACME query error: %v", err)
	}

	if len(resp2.Answer) != 1 {
		t.Fatalf("expected 1 answer for ACME TXT, got %d", len(resp2.Answer))
	}

	hash := sha256.Sum256([]byte("key-auth-xyz"))
	expectedTXT := base64.RawURLEncoding.EncodeToString(hash[:])

	if txtRecord, ok := resp2.Answer[0].(*dns.TXT); ok {
		if len(txtRecord.Txt) != 1 || txtRecord.Txt[0] != expectedTXT {
			t.Errorf("got TXT %v, want [%s]", txtRecord.Txt, expectedTXT)
		}
	} else {
		t.Errorf("expected TXT record, got %T", resp2.Answer[0])
	}
}

func TestDNSServerResolveProjectSubdomainAAndTXT(t *testing.T) {
	logger := zaptest.NewLogger(t)

	db, err := database.New("file::memory:?cache=shared", logger)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Insert domain with a custom project_subdomain
	domainRepo := database.NewDomainRepository(db)
	d := &domain.Domain{
		ID:                "domain-proj-123",
		DomainName:        "userapp.com",
		VerificationToken: "token-proj-123",
		ProjectSubdomain:  "proj-myproject123",
		Status:            domain.StatusPending,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	if err := domainRepo.Create(context.Background(), d); err != nil {
		t.Fatalf("failed to create domain: %v", err)
	}

	// Dynamic resolver mock returning 127.0.0.1
	r := NewDynamicResolver("example.com", time.Minute, logger)
	r.ipCache = "127.0.0.1"
	r.cacheTime = time.Now()

	s := NewDNSServer(DNSServerConfig{
		BaseDomain: "example.com",
		Resolver:   r,
		Logger:     logger,
		DB:         db,
		ListenAddr: "127.0.0.1:0",
	})

	localPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen local packet: %v", err)
	}
	s.server.PacketConn = localPC
	defer localPC.Close()

	go func() {
		if err := s.server.ActivateAndServe(); err != nil {
			logger.Error("local server err", zap.Error(err))
		}
	}()
	defer s.Shutdown()

	localAddr := localPC.LocalAddr().String()

	// Mock resolver lookup behavior: CNAME resolution of _acme-challenge.userapp.com -> _acme-challenge.proj-myproject123.example.com
	origResolver := net.DefaultResolver
	defer func() {
		net.DefaultResolver = origResolver
	}()

	mockMux := dns.NewServeMux()
	mockMux.HandleFunc("_acme-challenge.userapp.com.", func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true
		for _, q := range req.Question {
			if q.Qtype == dns.TypeCNAME {
				rr := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Target: "_acme-challenge.proj-myproject123.example.com.",
				}
				msg.Answer = append(msg.Answer, rr)
			}
		}
		w.WriteMsg(msg)
	})

	mockServer := &dns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "udp",
		Handler: mockMux,
	}
	mockPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock packet: %v", err)
	}
	mockServer.PacketConn = mockPC
	defer mockPC.Close()

	go func() {
		_ = mockServer.ActivateAndServe()
	}()
	defer mockServer.Shutdown()

	mockAddr := mockPC.LocalAddr().String()
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", mockAddr)
		},
	}

	// 1. Check A Record resolution for proj-myproject123.example.com.
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = time.Second

	msgA := new(dns.Msg)
	msgA.SetQuestion("proj-myproject123.example.com.", dns.TypeA)
	respA, _, err := c.Exchange(msgA, localAddr)
	if err != nil {
		t.Fatalf("A query error: %v", err)
	}
	if len(respA.Answer) != 1 {
		t.Fatalf("expected 1 answer for A query, got %d", len(respA.Answer))
	}
	if aRecord, ok := respA.Answer[0].(*dns.A); ok {
		if !aRecord.A.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("got IP %v, want 127.0.0.1", aRecord.A)
		}
	} else {
		t.Errorf("expected A record, got %T", respA.Answer[0])
	}

	// 2. Check TXT Record resolution for _acme-challenge.proj-myproject123.example.com.
	s.refreshPendingTXTCacheOnce(context.Background())

	msgTXT := new(dns.Msg)
	msgTXT.SetQuestion("_acme-challenge.proj-myproject123.example.com.", dns.TypeTXT)
	respTXT, _, err := c.Exchange(msgTXT, localAddr)
	if err != nil {
		t.Fatalf("TXT query error: %v", err)
	}
	if len(respTXT.Answer) != 1 {
		t.Fatalf("expected 1 answer for TXT query, got %d", len(respTXT.Answer))
	}
	if txtRecord, ok := respTXT.Answer[0].(*dns.TXT); ok {
		if len(txtRecord.Txt) != 1 || txtRecord.Txt[0] != "token-proj-123" {
			t.Errorf("got TXT %v, want [token-proj-123]", txtRecord.Txt)
		}
	} else {
		t.Errorf("expected TXT record, got %T", respTXT.Answer[0])
	}
}
