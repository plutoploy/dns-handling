package http

import (
	"encoding/json"
	"net"
	"net/http"

	"go.uber.org/zap"

	"plutoploy/tls/internal/dns"
)

type DNSHandler struct {
	dnsServer *dns.DNSServer
	logger    *zap.Logger
}

func NewDNSHandler(dnsServer *dns.DNSServer, logger *zap.Logger) *DNSHandler {
	return &DNSHandler{
		dnsServer: dnsServer,
		logger:    logger,
	}
}

type addRecordReq struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl"`
	Target string `json:"target,omitempty"`
	Pref   uint16 `json:"pref,omitempty"`
}

type recordResp struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl"`
	Target string `json:"target,omitempty"`
	Pref   uint16 `json:"pref,omitempty"`
}

type recordsResp struct {
	Static  []staticRecordResp  `json:"static"`
	Manual  []manualRecordResp  `json:"manual"`
}

type staticRecordResp struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type manualRecordResp struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl"`
	Target string `json:"target,omitempty"`
	Pref   uint16 `json:"pref,omitempty"`
}

type removeRecordReq struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (h *DNSHandler) AddRecord(w http.ResponseWriter, r *http.Request) {
	var req addRecordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: %v", err)
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	recType := dns.RecordType(req.Type)

	switch recType {
	case dns.RecordTypeA, dns.RecordTypeAAAA:
		if req.Value == "" {
			writeError(w, http.StatusBadRequest, "ip is required for A/AAAA records")
			return
		}
		ip := net.ParseIP(req.Value)
		if ip == nil {
			writeError(w, http.StatusBadRequest, "invalid IP address")
			return
		}
		h.dnsServer.AddStaticRecord(req.Name, ip)

	case dns.RecordTypeCNAME, dns.RecordTypeTXT, dns.RecordTypeMX, dns.RecordTypeSRV:
		if req.Value == "" {
			writeError(w, http.StatusBadRequest, "value is required")
			return
		}
		if req.TTL == 0 {
			req.TTL = 300
		}
		h.dnsServer.AddManualRecord(dns.ManualRecord{
			Name:   req.Name,
			Type:   recType,
			Value:  req.Value,
			TTL:    req.TTL,
			Target: req.Target,
			Pref:   req.Pref,
		})

	default:
		writeError(w, http.StatusBadRequest, "unsupported record type: %s", req.Type)
		return
	}

	writeJSON(w, http.StatusCreated, recordResp{
		Name:   req.Name,
		Type:   req.Type,
		Value:  req.Value,
		TTL:    req.TTL,
		Target: req.Target,
		Pref:   req.Pref,
	})
}

func (h *DNSHandler) RemoveRecord(w http.ResponseWriter, r *http.Request) {
	var req removeRecordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: %v", err)
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	recType := dns.RecordType(req.Type)

	switch recType {
	case dns.RecordTypeA, dns.RecordTypeAAAA:
		h.dnsServer.RemoveStaticRecord(req.Name)

	case dns.RecordTypeCNAME, dns.RecordTypeTXT, dns.RecordTypeMX, dns.RecordTypeSRV:
		if !h.dnsServer.RemoveManualRecord(req.Name, recType, req.Value) {
			writeError(w, http.StatusNotFound, "record not found")
			return
		}

	default:
		writeError(w, http.StatusBadRequest, "unsupported record type: %s", req.Type)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *DNSHandler) ListRecords(w http.ResponseWriter, r *http.Request) {
	staticRecords := h.dnsServer.GetRecords()
	manualRecords := h.dnsServer.GetManualRecords()

	resp := recordsResp{
		Static: make([]staticRecordResp, 0, len(staticRecords)),
		Manual: make([]manualRecordResp, 0),
	}

	for name, ip := range staticRecords {
		resp.Static = append(resp.Static, staticRecordResp{
			Name: name,
			IP:   ip.String(),
		})
	}

	for name, recs := range manualRecords {
		for _, rec := range recs {
			resp.Manual = append(resp.Manual, manualRecordResp{
				Name:   name,
				Type:   string(rec.Type),
				Value:  rec.Value,
				TTL:    rec.TTL,
				Target: rec.Target,
				Pref:   rec.Pref,
			})
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *DNSHandler) ResolveDomain(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name query parameter is required")
		return
	}

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "resolution failed: %v", err)
		return
	}

	type ipResp struct {
		IP string `json:"ip"`
	}

	resp := make([]ipResp, 0, len(ips))
	for _, ip := range ips {
		resp = append(resp, ipResp{IP: ip.IP.String()})
	}

	writeJSON(w, http.StatusOK, resp)
}
