package http

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"plutoploy/tls/internal/acme"
	"plutoploy/tls/internal/certificates"
	"plutoploy/tls/internal/dns"
	"plutoploy/tls/internal/domain"
)

type Handler struct {
	domainSvc *domain.Service
	certSvc   *certificates.Service
	acmeProv  acme.Provider
	dns       dns.Resolver
	logger    *zap.Logger
	pollInt   time.Duration
	pollTO    time.Duration
}

func NewHandler(
	domainSvc *domain.Service,
	certSvc *certificates.Service,
	acmeProv acme.Provider,
	dns dns.Resolver,
	logger *zap.Logger,
	pollInterval, pollTimeout time.Duration,
) *Handler {
	if domainSvc == nil {
		panic("http handler requires domain service")
	}
	if certSvc == nil {
		panic("http handler requires certificate service")
	}
	if acmeProv == nil {
		panic("http handler requires acme provider")
	}
	if dns == nil {
		panic("http handler requires dns resolver")
	}
	if logger == nil {
		panic("http handler requires logger")
	}
	return &Handler{
		domainSvc: domainSvc,
		certSvc:   certSvc,
		acmeProv:  acmeProv,
		dns:       dns,
		logger:    logger,
		pollInt:   pollInterval,
		pollTO:    pollTimeout,
	}
}

type createDomainReq struct {
	DomainName string `json:"domain_name"`
}

type createDomainResp struct {
	ID                string `json:"id"`
	DomainName        string `json:"domain_name"`
	VerificationToken string `json:"verification_token"`
	Status            string `json:"status"`
	Instructions      string `json:"instructions,omitempty"`
}

func (h *Handler) CreateDomain(w http.ResponseWriter, r *http.Request) {
	var req createDomainReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: %v", err)
		return
	}

	if req.DomainName == "" {
		writeError(w, http.StatusBadRequest, "domain_name is required")
		return
	}

	d, err := h.domainSvc.Create(r.Context(), req.DomainName)
	if err != nil {
		h.logger.Error("create domain", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "create domain: %v", err)
		return
	}

	challengeDomain := h.domainSvc.ChallengeDomain(d.DomainName)
	resp := createDomainResp{
		ID:                d.ID,
		DomainName:        d.DomainName,
		VerificationToken: d.VerificationToken,
		Status:            string(d.Status),
		Instructions:      fmt.Sprintf("Create a TXT record for %s with value: %s", challengeDomain, d.VerificationToken),
	}

	writeJSON(w, http.StatusCreated, resp)
}

type domainResp struct {
	ID         string  `json:"id"`
	DomainName string  `json:"domain_name"`
	Status     string  `json:"status"`
	VerifiedAt *string `json:"verified_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

func (h *Handler) GetDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	d, err := h.domainSvc.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	resp := domainResp{
		ID:         d.ID,
		DomainName: d.DomainName,
		Status:     string(d.Status),
		CreatedAt:  d.CreatedAt.Format(time.RFC3339),
	}

	if d.VerifiedAt != nil {
		v := d.VerifiedAt.Format(time.RFC3339)
		resp.VerifiedAt = &v
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	d, err := h.domainSvc.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	challengeDomain := h.domainSvc.ChallengeDomain(d.DomainName)

	records, err := h.dns.LookupTXT(r.Context(), challengeDomain)
	if err != nil {
		h.logger.Error("dns lookup", zap.String("domain", challengeDomain), zap.Error(err))
		writeError(w, http.StatusFailedDependency, "dns lookup failed: %v", err)
		return
	}

	updated, err := h.domainSvc.VerifyTXT(r.Context(), id, records)
	if err != nil {
		writeError(w, http.StatusBadRequest, "verification failed: %v", err)
		return
	}

	resp := domainResp{
		ID:         updated.ID,
		DomainName: updated.DomainName,
		Status:     string(updated.Status),
		CreatedAt:  updated.CreatedAt.Format(time.RFC3339),
	}

	if updated.VerifiedAt != nil {
		v := updated.VerifiedAt.Format(time.RFC3339)
		resp.VerifiedAt = &v
	}

	writeJSON(w, http.StatusOK, resp)
}

type issueCertResp struct {
	OrderID          string `json:"order_id"`
	Status           string `json:"status"`
	ChallengeDomain  string `json:"challenge_domain"`
	ExpectedTXTValue string `json:"expected_txt_value"`
	Instructions     string `json:"instructions"`
}

func (h *Handler) IssueCertificate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	d, err := h.domainSvc.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	if d.Status != domain.StatusVerified {
		writeError(w, http.StatusBadRequest, "domain must be verified first, current status: %s", d.Status)
		return
	}

	accountKey, accountKID, err := h.acmeProv.SetupAccount(r.Context())
	if err != nil {
		h.logger.Error("acme setup", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "acme setup failed: %v", err)
		return
	}

	order, challenge, err := h.acmeProv.StartOrder(r.Context(), d.ID, d.DomainName, accountKey, accountKID)
	if err != nil {
		h.logger.Error("acme start order", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "start acme order failed: %v", err)
		return
	}

	if _, err := h.domainSvc.SetCertificatePending(r.Context(), id); err != nil {
		h.logger.Error("set certificate pending", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "update status failed: %v", err)
		return
	}

	challengeDomain := h.domainSvc.ChallengeDomain(d.DomainName)

	go h.pollACME(d.ID, d.DomainName, accountKey, accountKID, order.ID, *challenge)

	resp := issueCertResp{
		OrderID:          order.ID,
		Status:           "certificate_pending",
		ChallengeDomain:  challengeDomain,
		ExpectedTXTValue: challenge.TXTValue,
		Instructions:     fmt.Sprintf("Update the TXT record for %s to: %s", challengeDomain, challenge.TXTValue),
	}

	writeJSON(w, http.StatusAccepted, resp)
}

func (h *Handler) pollACME(domainID, domainName string, accountKey crypto.Signer, accountKID, orderID string, ch acme.Challenge) {
	ctx := context.Background()
	pollCtx, cancel := context.WithTimeout(ctx, h.pollTO)
	defer cancel()

	ticker := time.NewTicker(h.pollInt)
	defer ticker.Stop()

	challengeDomain := fmt.Sprintf("_acme-challenge.%s.", domainName)

	for {
		select {
		case <-pollCtx.Done():
			h.logger.Error("acme polling timed out", zap.String("domain", domainName))
			if _, err := h.domainSvc.SetFailed(ctx, domainID); err != nil {
				h.logger.Error("set domain failed", zap.Error(err))
			}
			return

		case <-ticker.C:
			records, err := h.dns.LookupTXT(pollCtx, challengeDomain)
			if err != nil {
				h.logger.Debug("dns lookup failed during acme poll", zap.String("domain", challengeDomain), zap.Error(err))
				continue
			}

			found := false
			for _, rec := range records {
				if rec == ch.TXTValue {
					found = true
					break
				}
			}

			if !found {
				continue
			}

			h.logger.Info("acme dns-01 record found", zap.String("domain", domainName))

			certPEM, keyPEM, issuedAt, expiresAt, err := h.acmeProv.CompleteOrder(pollCtx, accountKey, accountKID, orderID, ch)
			if err != nil {
				h.logger.Error("acme complete order failed", zap.String("domain", domainName), zap.Error(err))
				if _, err := h.domainSvc.SetFailed(ctx, domainID); err != nil {
					h.logger.Error("set domain failed", zap.Error(err))
				}
				return
			}

			if _, err := h.certSvc.Store(ctx, domainID, certPEM, keyPEM, issuedAt, expiresAt); err != nil {
				h.logger.Error("store certificate failed", zap.String("domain", domainName), zap.Error(err))
				if _, err := h.domainSvc.SetFailed(ctx, domainID); err != nil {
					h.logger.Error("set domain failed", zap.Error(err))
				}
				return
			}

			if _, err := h.domainSvc.SetActive(ctx, domainID); err != nil {
				h.logger.Error("set domain active failed", zap.Error(err))
				return
			}

			h.logger.Info("certificate issued", zap.String("domain", domainName))
			return
		}
	}
}

type certificateResp struct {
	ID        string `json:"id"`
	DomainID  string `json:"domain_id"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

func (h *Handler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	d, err := h.domainSvc.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	if d.Status != domain.StatusActive {
		writeError(w, http.StatusNotFound, "no certificate issued yet, domain status: %s", d.Status)
		return
	}

	cert, err := h.certSvc.GetByDomainID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}

	resp := certificateResp{
		ID:        cert.ID,
		DomainID:  cert.DomainID,
		IssuedAt:  cert.IssuedAt.Format(time.RFC3339),
		ExpiresAt: cert.ExpiresAt.Format(time.RFC3339),
		CreatedAt: cert.CreatedAt.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	writeJSON(w, status, map[string]string{"error": msg})
}
