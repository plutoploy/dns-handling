package dns

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
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
	recordsMu     sync.RWMutex
}

type DNSServerConfig struct {
	ListenAddr string
	BaseDomain string
	Resolver   *DynamicResolver
	Logger     *zap.Logger
}

func NewDNSServer(cfg DNSServerConfig) *DNSServer {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":53"
	}

	zone := cfg.BaseDomain
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	s := &DNSServer{
		resolver:      cfg.Resolver,
		baseDomain:    cfg.BaseDomain,
		zone:          zone,
		logger:        cfg.Logger,
		records:       make(map[string]net.IP),
		manualRecords: make(map[string][]ManualRecord),
	}

	handler := dns.NewServeMux()
	handler.HandleFunc(s.zone, s.handleDNS)

	s.server = &dns.Server{
		Addr:    cfg.ListenAddr,
		Net:     "udp",
		Handler: handler,
	}

	return s
}

func (s *DNSServer) Start() error {
	s.logger.Info("starting DNS server", zap.String("addr", s.server.Addr), zap.String("zone", s.zone))

	if err := s.server.ListenAndServe(); err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}

	return nil
}

func (s *DNSServer) Shutdown() error {
	return s.server.Shutdown()
}

func (s *DNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
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
	defer s.recordsMu.RUnlock()

	var txts []string
	for _, rec := range s.manualRecords[name] {
		if rec.Type == RecordTypeTXT {
			txts = append(txts, rec.Value)
		}
	}
	return txts
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
	if len(subdomain) == 8 {
		b, err := hex.DecodeString(subdomain)
		if err != nil {
			return nil, fmt.Errorf("decode hex: %w", err)
		}
		if len(b) != 4 {
			return nil, fmt.Errorf("invalid IPv4 hex length")
		}
		return net.IPv4(b[0], b[1], b[2], b[3]), nil
	}

	if len(subdomain) == 32 {
		b, err := hex.DecodeString(subdomain)
		if err != nil {
			return nil, fmt.Errorf("decode hex: %w", err)
		}
		if len(b) != 16 {
			return nil, fmt.Errorf("invalid IPv6 hex length")
		}
		return net.IP(b), nil
	}

	return nil, fmt.Errorf("invalid subdomain length: %d", len(subdomain))
}

func (s *DNSServer) AddStaticRecord(name string, ip net.IP) {
	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()

	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	s.records[name] = ip
	s.logger.Info("added static record",
		zap.String("name", name),
		zap.String("ip", ip.String()),
	)
}

func (s *DNSServer) RemoveStaticRecord(name string) {
	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()

	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	delete(s.records, name)
	s.logger.Info("removed static record", zap.String("name", name))
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

func (s *DNSServer) AddManualRecord(rec ManualRecord) {
	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()

	name := strings.ToLower(rec.Name)
	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	s.manualRecords[name] = append(s.manualRecords[name], rec)
	s.logger.Info("added manual record",
		zap.String("name", name),
		zap.String("type", string(rec.Type)),
		zap.String("value", rec.Value),
	)
}

func (s *DNSServer) RemoveManualRecord(name string, recType RecordType, value string) bool {
	s.recordsMu.Lock()
	defer s.recordsMu.Unlock()

	name = strings.ToLower(name)
	if !strings.HasSuffix(name, s.zone) {
		name = name + "." + s.zone
	}

	recs, ok := s.manualRecords[name]
	if !ok {
		return false
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
			return true
		}
	}
	return false
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

func (s *DNSServer) UpdateStaticRecord(name string, ip net.IP) {
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
}
