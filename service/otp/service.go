package otp

import (
	"context"
	"log/slog"
	"time"

	"github.com/carafie/identity/platform/email"
	"github.com/carafie/identity/platform/requestid"
	"github.com/carafie/identity/platform/slogx"
	"github.com/carafie/identity/platform/sqlx"
)

type Service struct {
	otpStore    Store
	otpMailer   Mailer
	otpDuration time.Duration
	transactor  sqlx.Transactor
	logger      *slog.Logger
}

func (s *Service) Request(ctx context.Context, emailAddress string) (*OTP, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	em, err := email.Parse(emailAddress)
	if err != nil {
		l.WarnContext(ctx, "parse email", slogx.Error(err))
		return nil, err
	}
	otp := New(em, s.otpDuration)

	l = s.logger.With(slogx.OTPID(otp.ID.String()))

	err = s.transactor.Single(ctx, func(ctx context.Context, executor sqlx.Executor) error {
		if err := s.otpStore.Create(ctx, executor, otp); err != nil {
			l.ErrorContext(ctx, "create otp in store", slogx.Error(err))
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if err := s.otpMailer.SendRequest(ctx, otp); err != nil {
		l.ErrorContext(ctx, "send otp request email", slogx.Error(err))
		return nil, err
	}

	return otp, nil
}
