package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/auth/mailer"
	"github.com/carafie/identity/auth/store"
	"github.com/carafie/identity/platform/jwt"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/requestid"
	"github.com/carafie/identity/platform/slogx"
	"github.com/carafie/identity/platform/sqlx"
	"github.com/carafie/identity/platform/uuid"
)

type Service struct {
	store  store.Store
	mailer mailer.Mailer

	otpDuration    time.Duration
	otpMaxAttempts int

	tokenManager         *jwt.Manager
	tokenAccessDuration  time.Duration
	tokenRefreshDuration time.Duration

	transactor sqlx.Transactor
	logger     *slog.Logger
}

type Params struct {
	Store  store.Store
	Mailer mailer.Mailer

	OTPDuration    time.Duration
	OTPMaxAttempts int

	TokenManager         *jwt.Manager
	TokenAccessDuration  time.Duration
	TokenRefreshDuration time.Duration

	Transactor sqlx.Transactor
	Logger     *slog.Logger
}

func New(params *Params) *Service {
	if params.Store == nil {
		panic("store cannot be nil")
	}
	if params.Mailer == nil {
		panic("mailer cannot be nil")
	}
	if params.TokenManager == nil {
		panic("token manager cannot be nil")
	}
	if params.Transactor == nil {
		panic("transactor cannot be nil")
	}
	if params.Logger == nil {
		params.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		store:  params.Store,
		mailer: params.Mailer,

		otpDuration:    params.OTPDuration,
		otpMaxAttempts: params.OTPMaxAttempts,

		tokenManager:         params.TokenManager,
		tokenAccessDuration:  params.TokenAccessDuration,
		tokenRefreshDuration: params.TokenRefreshDuration,

		transactor: params.Transactor,
		logger:     params.Logger,
	}
}

func (s *Service) RequestOTP(ctx context.Context, email string) (*domain.OTP, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	parsedEmail, err := mail.Parse(email)
	if err != nil {
		l.WarnContext(ctx, "parse email", slogx.Error(err))
		return nil, err
	}
	otp := domain.NewOTP(parsedEmail, s.otpDuration)

	l = s.logger.With(slogx.OTPID(otp.ID))

	err = s.transactor.Single(ctx, func(ctx context.Context, executor sqlx.Executor) error {
		if err := s.store.CreateOTP(ctx, executor, otp); err != nil {
			l.ErrorContext(ctx, "create otp in store", slogx.Error(err))
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if err := s.mailer.SendOTPRequest(ctx, otp); err != nil {
		l.ErrorContext(ctx, "send otp request email", slogx.Error(err))
		return nil, err
	}

	return otp, nil
}

func (s *Service) ConfirmOTP(ctx context.Context, otpID, code string) (*domain.AccessToken, *domain.RefreshToken, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	parsedOTPID, err := uuid.Parse(otpID)
	if err != nil {
		l.WarnContext(ctx, "parse otp id", slogx.Error(err))
		return nil, nil, err
	}
	parsedCode, err := domain.ParseCode(code)
	if err != nil {
		l.WarnContext(ctx, "parse otp code", slogx.Error(err))
		return nil, nil, err
	}

	var (
		access  *domain.AccessToken
		refresh *domain.RefreshToken
	)
	err = s.transactor.Atomic(ctx, func(ctx context.Context, executor sqlx.Executor) (sqlx.TCL, error) {
		otp, err := s.store.ConsumeOTP(ctx, executor, parsedOTPID)
		if err != nil {
			if errors.Is(err, sqlx.ErrNotFound) {
				l.WarnContext(ctx, "consume otp in store", slogx.Error(err))
				return sqlx.Rollback, domain.ErrCodeExpired
			}
			l.ErrorContext(ctx, "consume otp in store", slogx.Error(err))
			return sqlx.Rollback, err
		}
		if err := otp.Validate(parsedCode, s.otpMaxAttempts); err != nil {
			if errors.Is(err, domain.ErrCodeMismatched) {
				return sqlx.Commit, err
			}
			return sqlx.Rollback, err
		}

		user, err := s.store.GetUserByEmailOrCreate(ctx, executor, domain.NewUser(otp.Email))
		if err != nil {
			l.ErrorContext(ctx, "get user by email or create in store", slogx.Error(err))
			return sqlx.Rollback, err
		}

		innerAccess, innerRefresh, err := s.issueTokens(user)
		if err != nil {
			l.ErrorContext(ctx, "issue tokens", slogx.Error(err))
			return sqlx.Rollback, err
		}
		if err := s.store.CreateRefreshToken(ctx, executor, innerRefresh); err != nil {
			l.ErrorContext(ctx, "create refresh token in store", slogx.Error(err))
			return sqlx.Rollback, err
		}
		access = innerAccess
		refresh = innerRefresh

		return sqlx.Commit, nil
	})
	return access, refresh, err
}

func (s *Service) issueTokens(user *domain.User) (*domain.AccessToken, *domain.RefreshToken, error) {
	access, err := s.tokenManager.Sign(
		jwt.NewTokenFields(user.ID, user.Email, jwt.KindAccess, s.tokenAccessDuration),
	)
	if err != nil {
		return nil, nil, err
	}
	refresh, err := s.tokenManager.Sign(
		jwt.NewTokenFields(user.ID, user.Email, jwt.KindRefresh, s.tokenRefreshDuration),
	)
	if err != nil {
		return nil, nil, err
	}
	return access, refresh, nil
}
