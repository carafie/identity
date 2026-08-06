package otp

import (
	"context"
	"log/slog"
	"time"

	"github.com/carafie/identity/platform/mail"
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

type ServiceParams struct {
	OTPStore    Store
	OTPMailer   Mailer
	OTPDuration time.Duration
	Transactor  sqlx.Transactor
	Logger      *slog.Logger
}

func NewService(params *ServiceParams) *Service {
	if params.OTPStore == nil {
		panic("otp store cannot be nil")
	}
	if params.OTPMailer == nil {
		panic("otp mailer cannot be nil")
	}
	if params.Transactor == nil {
		panic("transactor cannot be nil")
	}
	if params.Logger == nil {
		params.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		otpStore:    params.OTPStore,
		otpMailer:   params.OTPMailer,
		otpDuration: params.OTPDuration,
		transactor:  params.Transactor,
		logger:      params.Logger,
	}
}

func (s *Service) Request(ctx context.Context, email string) (*OTP, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	parsedEmail, err := mail.Parse(email)
	if err != nil {
		l.WarnContext(ctx, "parse email", slogx.Error(err))
		return nil, err
	}
	otp := New(parsedEmail, s.otpDuration)

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
