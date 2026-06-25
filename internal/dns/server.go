package dns

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"plutoploy/tls/internal/database"
)

type RecordType string

const (
	RecordTypeA     RecordType = "A"
	RecordTypeAAAA  RecordType = "AAAA"
	RecordTypeCNAME RecordType = "CNAME"
	RecordTypeTXT   RecordType = "TXT"
	RecordTypeMX    RecordType = "MX"
	RecordTypeSRV   RecordType = "SRV"
)

type ManualRecord struct {
	Name   string
	Type   RecordType
	Value  string
	TTL    uint32
	Target string
	Pref   uint16
}

type DNSServer struct {
	server        *dns.Server
	resolver      *DynamicResolver
	baseDomain    string
	zone          string
	logger        *zap.Logger
	records       map[string]net.IP
	manualRecords map[string][]ManualRecord
	pendingTXT    map[string][]string
	recordsMu     sync.RWMutex
	cacheMu       sync.RWMutex
	upstreams     []string
	db            *database.DB
}

type DNSServerConfig struct {
	ListenAddr string
	BaseDomain string
	Resolver   *DynamicResolver
	Logger     *zap.Logger
	Upstreams  []string
	DB         *database.DB
}

func NewDNSServer(cfg DNSServerConfig) *DNSServer {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":53"
	}

	zone := cfg.BaseDomain
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	upstreams := cfg.Upstreams
	if len(upstreams) == 0 {
		upstreams = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	s := &DNSServer{
		resolver:      cfg.Resolver,
		baseDomain:    cfg.BaseDomain,
		zone:          zone,
		logger:        cfg.Logger,
		records:       make(map[string]net.IP),
		manualRecords: make(map[string][]ManualRecord),
		pendingTXT:    make(map[string][]string),
		upstreams:     upstreams,
		db:            cfg.DB,
	}

	handler := dns.NewServeMux()
	handler.HandleFunc(".", s.handleDNS)

	s.server = &dns.Server{
		Addr:    cfg.ListenAddr,
		Net:     "udp",
		Handler: handler,
	}

	return s
}

func (s *DNSServer) BaseDomain() string {
	return s.baseDomain
}

func (s *DNSServer) Start(ctx context.Context) error {
	if err := s.loadPersistedRecords(ctx); err != nil {
		return err
	}

	if s.db != nil {
		s.refreshPendingTXTCacheOnce(ctx)
		go s.refreshPendingTXTCache(ctx)
	}

	s.logger.Info("starting DNS server", zap.String("addr", s.server.Addr), zap.String("zone", s.zone))

	if err := s.server.ListenAndServe(); err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}

	return nil
}

func (s *DNSServer) Shutdown() error {
	return s.server.Shutdown()
}

func (s *DNSServer) loadPersistedRecords(ctx context.Context) error {
	if s.db == nil {
		return nil
	}

	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()

	s.records = make(map[string]net.IP)
	s.manualRecords = make(map[string][]ManualRecord)

	rows, err := s.db.QueryContext(ctx, `SELECT name, ip FROM dns_static_records`)
	if err != nil {
		return fmt.Errorf("load static records: %w", err)
	}
	for rows.Next() {
		var name, ipStr string
		if err := rows.Scan(&name, &ipStr); err != nil {
			rows.Close()
			return fmt.Errorf("scan static record: %w", err)
		}
		if ip := net.ParseIP(ipStr); ip != nil {
			s.records[strings.ToLower(name)] = ip
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate static records: %w", err)
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `SELECT name, record_type, value, ttl, target, pref FROM dns_manual_records ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("load manual records: %w", err)
	}
	for rows.Next() {
		var rec ManualRecord
		var recType string
		if err := rows.Scan(&rec.Name, &recType, &rec.Value, &rec.TTL, &rec.Target, &rec.Pref); err != nil {
			rows.Close()
			return fmt.Errorf("scan manual record: %w", err)
		}
		rec.Type = RecordType(recType)
		rec.Name = strings.ToLower(rec.Name)
		if !strings.HasSuffix(rec.Name, s.zone) {
			rec.Name = rec.Name + "." + s.zone
		}
		s.manualRecords[rec.Name] = append(s.manualRecords[rec.Name], rec)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate manual records: %w", err)
	}
	rows.Close()

	return nil
}

func (s *DNSServer) refreshPendingTXTCache(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	s.refreshPendingTXTCacheOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshPendingTXTCacheOnce(ctx)
		}
	}
}

func (s *DNSServer) refreshPendingTXTCacheOnce(ctx context.Context) {
	if s.db == nil {
		return
	}

	cache := make(map[string][]string)
	verificationCache := make(map[string][]string)
	acmeCache := make(map[string][]string)

	rows, err := s.db.QueryContext(ctx, "SELECT domain_name, verification_token FROM domains WHERE status = 'pending'")
	if err == nil {
		for rows.Next() {
			var domainName, token string
			if err := rows.Scan(&domainName, &token); err == nil {
				if hexIP := s.resolveDomainHexIP(ctx, domainName); hexIP != "" {
					verificationCache[hexIP] = append(verificationCache[hexIP], token)
				}
			}
		}
		rows.Close()
	}

	rows, err = s.db.QueryContext(ctx,
		`SELECT d.domain_name, c.key_authorization
		 FROM acme_challenges c
		 JOIN domains d ON c.domain_id = d.id
		 WHERE c.status = 'pending'`)
	if err == nil {
		for rows.Next() {
			var domainName, keyAuth string
			if err := rows.Scan(&domainName, &keyAuth); err == nil {
				if hexIP := s.resolveDomainHexIP(ctx, domainName); hexIP != "" {
					h := sha256.Sum256([]byte(keyAuth))
					txtVal := base64.RawURLEncoding.EncodeToString(h[:])
					acmeCache[hexIP] = append(acmeCache[hexIP], txtVal)
				}
			}
		}
		rows.Close()
	}

	for hexIP, records := range verificationCache {
		cache[hexIP] = append(cache[hexIP], records...)
	}
	for hexIP, records := range acmeCache {
		if len(cache[hexIP]) == 0 {
			cache[hexIP] = append(cache[hexIP], records...)
		}
	}

	s.cacheMu.Lock()
	s.pendingTXT = cache
	s.cacheMu.Unlock()
}

func (s *DNSServer) resolveDomainHexIP(ctx context.Context, domainName string) string {
	challengeDomain := "_acme-challenge." + domainName
	cname, err := net.DefaultResolver.LookupCNAME(ctx, challengeDomain)
	if err == nil {
		cnameClean := strings.TrimSuffix(cname, ".")
		if hexIP := extractHexIPFromDomain(cnameClean, s.baseDomain); hexIP != "" {
			return hexIP
		}
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domainName)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if ipHex := encodeIPToHex(ip.IP); ipHex != "" {
			return ipHex
		}
	}
	return ""
}

func encodeIPToHex(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%02x%02x%02x%02x", v4[0], v4[1], v4[2], v4[3])
	}

	v6 := ip.To16()
	if v6 == nil {
		return ""
	}

	return hex.EncodeToString(v6)
}

func (s *DNSServer) forwardQuery(w dns.ResponseWriter, r *dns.Msg) {
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 5 * time.Second

	upstreams := s.upstreams
	var resp *dns.Msg
	var err error

	for _, upstream := range upstreams {
		resp, _, err = c.Exchange(r, upstream)
		if err == nil {
			break
		}
	}

	if err != nil {
		s.logger.Warn("failed to forward DNS query", zap.Error(err))
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	w.WriteMsg(resp)
}

func (s *DNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) > 0 {
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		if !strings.HasSuffix(name, s.zone) {
			s.forwardQuery(w, r)
			return
		}
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			records := s.resolveA(q.Name)
			for _, ip := range records {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: ip,
				}
				msg.Answer = append(msg.Answer, rr)
			}

		case dns.TypeAAAA:
			records := s.resolveAAAA(q.Name)
			for _, ip := range records {
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					AAAA: ip,
				}
				msg.Answer = append(msg.Answer, rr)
			}

		case dns.TypeCNAME:
			records := s.resolveCNAME(q.Name)
			for _, target := range records {
				rr := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Target: target,
				}
				msg.Answer = append(msg.Answer, rr)
			}

		case dns.TypeTXT:
			records := s.resolveTXT(q.Name)
			for _, txt := range records {
				rr := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Txt: []string{txt},
				}
				msg.Answer = append(msg.Answer, rr)
			}

		case dns.TypeMX:
			records := s.resolveMX(q.Name)
			for _, mx := range records {
				rr := &dns.MX{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Preference: mx.Pref,
					Mx:         mx.Target,
				}
				msg.Answer = append(msg.Answer, rr)
			}

		case dns.TypeSOA:
			rr := &dns.SOA{
				Hdr: dns.RR_Header{
					Name:   s.zone,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Ns:      "ns1." + s.zone,
				Mbox:    "admin." + s.zone,
				Serial:  uint32(time.Now().Unix()),
				Refresh: 3600,
				Retry:   600,
				Expire:  604800,
				Minttl:  60,
			}
			msg.Answer = append(msg.Answer, rr)

		case dns.TypeNS:
			rr := &dns.NS{
				Hdr: dns.RR_Header{
					Name:   s.zone,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Ns: "ns1." + s.zone,
			}
			msg.Answer = append(msg.Answer, rr)
		}
	}

	w.WriteMsg(msg)
}

func (s *DNSServer) resolveA(name string) []net.IP {
	name = strings.ToLower(name)

	s.recordsMu.RLock()
	if ip, ok := s.records[name]; ok {
		s.recordsMu.RUnlock()
		if ip4 := ip.To4(); ip4 != nil {
			return []net.IP{ip4}
		}
		return nil
	}
	s.recordsMu.RUnlock()

	if !strings.HasSuffix(name, s.zone) {
		return nil
	}

	subdomain := strings.TrimSuffix(name, s.zone)
	subdomain = strings.TrimSuffix(subdomain, ".")

	ip, err := s.decodeSubdomainToIP(subdomain)
	if err != nil {
		s.logger.Debug("failed to decode subdomain",
			zap.String("name", name),
			zap.Error(err),
		)
		return nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		s.recordsMu.Lock()
		s.records[name] = ip
		s.recordsMu.Unlock()

		s.logger.Debug("resolved domain",
			zap.String("name", name),
			zap.String("ip", ip4.String()),
		)

		return []net.IP{ip4}
	}

	return nil
}

func (s *DNSServer) resolveAAAA(name string) []net.IP {
	name = strings.ToLower(name)

	s.recordsMu.RLock()
	if ip, ok := s.records[name]; ok {
		s.recordsMu.RUnlock()
		if ip.To4() == nil {
			return []net.IP{ip}
		}
		return nil
	}
	s.recordsMu.RUnlock()

	if !strings.HasSuffix(name, s.zone) {
		return nil
	}

	subdomain := strings.TrimSuffix(name, s.zone)
	subdomain = strings.TrimSuffix(subdomain, ".")

	ip, err := s.decodeSubdomainToIP(subdomain)
	if err != nil {
		return nil
	}

	if ip.To4() == nil {
		s.recordsMu.Lock()
		s.records[name] = ip
		s.recordsMu.Unlock()

		s.logger.Debug("resolved domain",
			zap.String("name", name),
			zap.String("ip", ip.String()),
		)

		return []net.IP{ip}
	}

	return nil
}

func (s *DNSServer) resolveCNAME(name string) []string {
	name = strings.ToLower(name)

	s.recordsMu.RLock()
	defer s.recordsMu.RUnlock()

	var targets []string
	for _, rec := range s.manualRecords[name] {
		if rec.Type == RecordTypeCNAME {
			targets = append(targets, rec.Value)
		}
	}
	return targets
}

func (s *DNSServer) resolveTXT(name string) []string {
	name = strings.ToLower(name)

	s.recordsMu.RLock()
	var txts []string
	for _, rec := range s.manualRecords[name] {
		if rec.Type == RecordTypeTXT {
			txts = append(txts, rec.Value)
		}
	}
	s.recordsMu.RUnlock()

	if len(txts) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		dbTxts := s.lookupPendingTXTRecord(ctx, name)
		cancel()
		if len(dbTxts) > 0 {
			return dbTxts
		}
	}

	return txts
}

func extractHexIPFromDomain(domainName, baseDomain string) string {
	domainName = strings.TrimSuffix(domainName, ".")
	baseDomain = strings.TrimSuffix(baseDomain, ".")
	if !strings.HasSuffix(domainName, baseDomain) {
		return ""
	}
	subdomain := strings.TrimSuffix(domainName, baseDomain)
	subdomain = strings.TrimSuffix(subdomain, ".")

	labels := strings.Split(subdomain, ".")
	if len(labels) == 0 {
		return ""
	}
	lastLabel := labels[len(labels)-1]

	parts := strings.Split(lastLabel, "-")
	if len(parts) == 0 {
		return ""
	}
	lastPart := parts[len(parts)-1]

	if len(lastPart) == 8 || len(lastPart) == 32 {
		return lastPart
	}
	return ""
}

func (s *DNSServer) domainMatchesHexIP(ctx context.Context, domainName, hexIP string) bool {
	challengeDomain := "_acme-challenge." + domainName
	cname, err := net.DefaultResolver.LookupCNAME(ctx, challengeDomain)
	if err == nil {
		cnameClean := strings.TrimSuffix(cname, ".")
		if extractHexIPFromDomain(cnameClean, s.baseDomain) == hexIP {
			return true
		}
	}

	targetIP, err := s.decodeSubdomainToIP(hexIP)
	if err == nil {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, domainName)
		if err == nil {
			for _, ip := range ips {
				if ip.IP.Equal(targetIP) {
					return true
				}
			}
		}
	}

	return false
}

func (s *DNSServer) lookupPendingTXTRecord(ctx context.Context, name string) []string {
	hexIP := extractHexIPFromDomain(name, s.baseDomain)
	if hexIP == "" {
		return nil
	}

	s.cacheMu.RLock()
	records := append([]string(nil), s.pendingTXT[hexIP]...)
	s.cacheMu.RUnlock()

	if len(records) > 0 {
		return records
	}

	return nil
}

func (s *DNSServer) resolveMX(name string) []ManualRecord {
	name = strings.ToLower(name)

	s.recordsMu.RLock()
	defer s.recordsMu.RUnlock()

	var mxs []ManualRecord
	for _, rec := range s.manualRecords[name] {
		if rec.Type == RecordTypeMX {
			mxs = append(mxs, rec)
		}
	}
	return mxs
}

func (s *DNSServer) decodeSubdomainToIP(subdomain string) (net.IP, error) {
	dotParts := strings.Split(strings.TrimSuffix(subdomain, "."), ".")
	for i := len(dotParts) - 1; i >= 0; i-- {
		for _, candidate := range strings.Split(dotParts[i], "-") {
			label := strings.TrimPrefix(candidate, "dns-")
			label = strings.TrimPrefix(label, "dns.")
			label = strings.TrimPrefix(label, "dns")
			label = strings.TrimPrefix(label, "-")

			switch len(label) {
			case 8:
				b, err := hex.DecodeString(label)
				if err != nil {
					continue
				}
				if len(b) != 4 {
					continue
				}
				return net.IPv4(b[0], b[1], b[2], b[3]), nil
			case 32:
				b, err := hex.DecodeString(label)
				if err != nil {
					continue
				}
				if len(b) != 16 {
					continue
				}
				return net.IP(b), nil
			}
		}
	}

	return nil, fmt.Errorf("invalid subdomain: %s", subdomain)
}

func (s *DNSServer) AddStaticRecord(name string, ip net.IP) error {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	if s.db != nil {
		if _, err := s.db.ExecContext(context.Background(),
			`INSERT INTO dns_static_records (name, ip, updated_at)
			 VALUES (?, ?, CURRENT_TIMESTAMP)
			 ON CONFLICT(name) DO UPDATE SET ip = excluded.ip, updated_at = CURRENT_TIMESTAMP`,
			strings.ToLower(name), ip.String(),
		); err != nil {
			return fmt.Errorf("persist static record: %w", err)
		}
	}

	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()
	s.records[name] = ip
	s.logger.Info("added static record",
		zap.String("name", name),
		zap.String("ip", ip.String()),
	)
	return nil
}

func (s *DNSServer) RemoveStaticRecord(name string) error {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	if s.db != nil {
		if _, err := s.db.ExecContext(context.Background(),
			`DELETE FROM dns_static_records WHERE name = ?`,
			strings.ToLower(name),
		); err != nil {
			return fmt.Errorf("delete static record: %w", err)
		}
	}

	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()
	delete(s.records, name)
	s.logger.Info("removed static record", zap.String("name", name))
	return nil
}

func (s *DNSServer) GetRecords() map[string]net.IP {
	s.recordsMu.RLock()
	defer s.recordsMu.RUnlock()

	records := make(map[string]net.IP, len(s.records))
	for k, v := range s.records {
		records[k] = v
	}
	return records
}

func (s *DNSServer) AddManualRecord(rec ManualRecord) error {
	name := strings.ToLower(rec.Name)
	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	if s.db != nil {
		if _, err := s.db.ExecContext(context.Background(),
			`INSERT INTO dns_manual_records (name, record_type, value, ttl, target, pref, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
			name, string(rec.Type), rec.Value, rec.TTL, rec.Target, rec.Pref,
		); err != nil {
			return fmt.Errorf("persist manual record: %w", err)
		}
	}

	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()
	rec.Name = name
	s.manualRecords[name] = append(s.manualRecords[name], rec)
	s.logger.Info("added manual record",
		zap.String("name", name),
		zap.String("type", string(rec.Type)),
		zap.String("value", rec.Value),
	)
	return nil
}

func (s *DNSServer) RemoveManualRecord(name string, recType RecordType, value string) (bool, error) {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	if s.db != nil {
		if _, err := s.db.ExecContext(context.Background(),
			`DELETE FROM dns_manual_records
			 WHERE id IN (
			   SELECT id FROM dns_manual_records
			   WHERE name = ? AND record_type = ? AND value = ?
			   ORDER BY id ASC
			   LIMIT 1
			 )`,
			name, string(recType), value,
		); err != nil {
			return false, fmt.Errorf("delete manual record: %w", err)
		}
	}

	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()
	recs, ok := s.manualRecords[name]
	if !ok {
		return false, nil
	}

	for i, rec := range recs {
		if rec.Type == recType && rec.Value == value {
			s.manualRecords[name] = append(recs[:i], recs[i+1:]...)
			if len(s.manualRecords[name]) == 0 {
				delete(s.manualRecords, name)
			}
			s.logger.Info("removed manual record",
				zap.String("name", name),
				zap.String("type", string(recType)),
				zap.String("value", value),
			)
			return true, nil
		}
	}
	return false, nil
}

func (s *DNSServer) GetManualRecords() map[string][]ManualRecord {
	s.recordsMu.RLock()
	defer s.recordsMu.RUnlock()

	records := make(map[string][]ManualRecord, len(s.manualRecords))
	for k, v := range s.manualRecords {
		records[k] = v
	}
	return records
}

func (s *DNSServer) UpdateStaticRecord(name string, ip net.IP) error {
	name = strings.ToLower(name)
	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()

	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	s.records[name] = ip
	s.logger.Info("updated static record",
		zap.String("name", name),
		zap.String("ip", ip.String()),
	)
	return nil
}
