package http

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(h *Handler, dnsH *DNSHandler, authToken string) chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	r.Route("/domains", func(r chi.Router) {
		r.Use(BearerAuth(authToken))
		r.Post("/", h.CreateDomain)
		r.Get("/{id}", h.GetDomain)
		r.Post("/{id}/verify", h.VerifyDomain)
		r.Post("/{id}/issue-certificate", h.IssueCertificate)
		r.Get("/{id}/certificate", h.GetCertificate)
	})

	if dnsH != nil {
		r.Route("/dns", func(r chi.Router) {
			r.Use(BearerAuth(authToken))
			r.Get("/records", dnsH.ListRecords)
			r.Post("/records", dnsH.AddRecord)
			r.Delete("/records", dnsH.RemoveRecord)
			r.Get("/resolve", dnsH.ResolveDomain)
		})
	}

	return r
}
