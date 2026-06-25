package http

import (
	"context"

	"go.uber.org/zap"

	"plutoploy/tls/internal/domain"
)

func (h *Handler) ResumePendingACME(ctx context.Context) error {
	domains, err := h.domainSvc.ListByStatus(ctx, domain.StatusCertificatePending)
	if err != nil {
		return err
	}

	if len(domains) == 0 {
		return nil
	}

	accountKey, accountKID, err := h.acmeProv.SetupAccount(ctx)
	if err != nil {
		return err
	}

	for _, d := range domains {
		order, err := h.acmeProv.GetOrderByDomainID(ctx, d.ID)
		if err != nil {
			h.logger.Warn("skip pending acme domain: order missing", zap.String("domain", d.DomainName), zap.Error(err))
			continue
		}

		challenge, err := h.acmeProv.GetChallengeByDomainID(ctx, d.ID)
		if err != nil {
			h.logger.Warn("skip pending acme domain: challenge missing", zap.String("domain", d.DomainName), zap.Error(err))
			continue
		}

		go h.pollACME(h.appCtx, d.ID, d.DomainName, accountKey, accountKID, order.ID, *challenge)
	}

	return nil
}
