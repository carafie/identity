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

		innerAccess, err := s.issueAccessToken(user)
		if err != nil {
			l.ErrorContext(ctx, "issue access token", slogx.Error(err))
			return sqlx.Rollback, err
		}
		innerRefresh, err := s.issueRefreshToken(user)
		if err != nil {
			l.ErrorContext(ctx, "issue refresh token", slogx.Error(err))
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

func (s *Service) RefreshAccessToken(ctx context.Context, refreshJWS string) (*domain.AccessToken, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	refreshToken, err := s.tokenManager.Parse(refreshJWS) // expired tokens fail as well
	if err != nil {
		l.WarnContext(ctx, "parse refresh token", slogx.Error(err))
		return nil, domain.ErrTokenInvalid
	}
	if refreshToken.Fields.Kind != jwt.KindRefresh {
		l.WarnContext(ctx, "token kind mismatch")
		return nil, domain.ErrTokenInvalid
	}

	var tokenRevoked bool
	err = s.transactor.Single(ctx, func(ctx context.Context, executor sqlx.Executor) error {
		revoked, err := s.store.RefreshTokenRevoked(ctx, executor, refreshToken.Fields.ID)
		if err != nil {
			if errors.Is(err, sqlx.ErrNotFound) {
				l.WarnContext(ctx, "is refresh token revoked", slogx.Error(err))
				return domain.ErrTokenExpired
			}
			l.ErrorContext(ctx, "is refresh token revoked", slogx.Error(err))
			return err
		}
		tokenRevoked = revoked
		return nil
	})
	if err != nil {
		return nil, err
	}
	if tokenRevoked {
		return nil, domain.ErrTokenRevoked
	}

	return s.issueAccessToken(domain.LoadUser(refreshToken.Fields.UserID, refreshToken.Fields.Email))
}

func (s *Service) ListRefreshTokens(ctx context.Context, accessJWS string) ([]*domain.RefreshTokenFields, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	accessToken, err := s.tokenManager.Parse(accessJWS) // expired tokens fail as well
	if err != nil {
		l.WarnContext(ctx, "parse access token", slogx.Error(err))
		return nil, domain.ErrTokenInvalid
	}
	if accessToken.Fields.Kind != jwt.KindAccess {
		l.WarnContext(ctx, "token kind mismatch")
		return nil, domain.ErrTokenInvalid
	}

	var accessTokens []*domain.AccessTokenFields
	err = s.transactor.Single(ctx, func(ctx context.Context, executor sqlx.Executor) error {
		tokens, err := s.store.ListRefreshTokens(ctx, executor, accessToken.Fields.UserID)
		if err != nil {
			l.ErrorContext(ctx, "list refresh tokens from store", slogx.Error(err))
			return err
		}
		accessTokens = tokens
		return nil
	})
	return accessTokens, err
}

func (s *Service) issueAccessToken(user *domain.User) (*domain.AccessToken, error) {
	return s.tokenManager.Sign(
		jwt.NewTokenFields(user.ID, user.Email, jwt.KindAccess, s.tokenAccessDuration),
	)
}

func (s *Service) issueRefreshToken(user *domain.User) (*domain.AccessToken, error) {
	return s.tokenManager.Sign(
		jwt.NewTokenFields(user.ID, user.Email, jwt.KindRefresh, s.tokenRefreshDuration),
	)
}
