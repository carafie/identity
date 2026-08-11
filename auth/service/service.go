package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/auth/mailer"
	"github.com/carafie/identity/auth/store"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/requestid"
	"github.com/carafie/identity/platform/slogx"
	"github.com/carafie/identity/platform/sqlx"
	"github.com/carafie/identity/platform/uuid"
)

type Service struct {
	storeProvider store.Provider
	mailer        mailer.Mailer

	otpDuration    time.Duration
	otpMaxAttempts int

	tokenManager         *domain.TokenManager
	tokenAccessDuration  time.Duration
	tokenRefreshDuration time.Duration

	transactor sqlx.Transactor
	logger     *slog.Logger
}

type Params struct {
	StoreProvider store.Provider
	Mailer        mailer.Mailer

	OTPDuration    time.Duration
	OTPMaxAttempts int

	TokenManager         *domain.TokenManager
	TokenAccessDuration  time.Duration
	TokenRefreshDuration time.Duration

	Transactor sqlx.Transactor
	Logger     *slog.Logger
}

func New(params *Params) *Service {
	if params.StoreProvider == nil {
		panic("store provider cannot be nil")
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
		storeProvider: params.StoreProvider,
		mailer:        params.Mailer,

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
		store := s.storeProvider.New(executor)
		if err := store.CreateOTP(ctx, otp); err != nil {
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

func (s *Service) ConfirmOTP(ctx context.Context, otpID, code string) (
	*domain.AccessToken, *domain.RefreshToken, error,
) {
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
		accessToken  *domain.AccessToken
		refreshToken *domain.RefreshToken
	)
	err = s.transactor.Atomic(ctx, func(ctx context.Context, executor sqlx.Executor) (sqlx.TCL, error) {
		store := s.storeProvider.New(executor)

		otp, err := store.ConsumeOTP(ctx, parsedOTPID)
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

		if err := store.DeleteOTP(ctx, otp.ID); err != nil {
			l.ErrorContext(ctx, "delete otp from store", slogx.Error(err))
			return sqlx.Rollback, err
		}

		user, err := store.GetUserByEmailOrCreate(ctx, domain.NewUser(otp.Email))
		if err != nil {
			l.ErrorContext(ctx, "get user by email or create in store", slogx.Error(err))
			return sqlx.Rollback, err
		}

		access := domain.NewAccessToken(user.ID, user.Email, s.tokenAccessDuration)
		if err := s.tokenManager.SignAccess(access); err != nil {
			l.ErrorContext(ctx, "sign access token", slogx.Error(err))
			return sqlx.Rollback, err
		}
		refresh := domain.NewRefreshToken(user.ID, user.Email, s.tokenRefreshDuration)
		if err := s.tokenManager.SignRefresh(refresh); err != nil {
			l.ErrorContext(ctx, "sign refresh token", slogx.Error(err))
			return sqlx.Rollback, err
		}
		if err := store.CreateRefreshToken(ctx, refresh); err != nil {
			l.ErrorContext(ctx, "create refresh token in store", slogx.Error(err))
			return sqlx.Rollback, err
		}
		accessToken = access
		refreshToken = refresh

		return sqlx.Commit, nil
	})
	return accessToken, refreshToken, err
}

func (s *Service) RefreshAccessToken(ctx context.Context, refreshJWS string) (*domain.AccessToken, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	refreshToken, err := s.tokenManager.ParseRefresh(refreshJWS)
	if err != nil {
		l.WarnContext(ctx, "parse refresh token", slogx.Error(err))
		return nil, domain.ErrTokenInvalid
	}

	var exists bool
	err = s.transactor.Single(ctx, func(ctx context.Context, executor sqlx.Executor) error {
		store := s.storeProvider.New(executor)
		if _, err := store.GetRefreshToken(ctx, refreshToken.UserID, refreshToken.ID); err != nil {
			if errors.Is(err, sqlx.ErrNotFound) {
				l.WarnContext(ctx, "is refresh token in store", slogx.Error(err))
				exists = false
				return nil
			}
			l.ErrorContext(ctx, "is refresh token in store", slogx.Error(err))
			return err
		}
		exists = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, domain.ErrTokenNotFound
	}

	accessToken := domain.NewAccessToken(refreshToken.UserID, refreshToken.Email, s.tokenAccessDuration)
	return accessToken, s.tokenManager.SignAccess(accessToken)
}

func (s *Service) ListRefreshTokens(ctx context.Context, accessJWS string) ([]*domain.RefreshToken, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	accessToken, err := s.tokenManager.ParseAccess(accessJWS)
	if err != nil {
		l.WarnContext(ctx, "parse access token", slogx.Error(err))
		return nil, domain.ErrTokenInvalid
	}

	var refreshTokens []*domain.RefreshToken
	err = s.transactor.Single(ctx, func(ctx context.Context, executor sqlx.Executor) error {
		store := s.storeProvider.New(executor)
		tokens, err := store.ListRefreshTokens(ctx, accessToken.UserID)
		if err != nil {
			l.ErrorContext(ctx, "list refresh tokens from store", slogx.Error(err))
			return err
		}
		refreshTokens = tokens
		return nil
	})
	return refreshTokens, err
}

func (s *Service) DeleteRefreshToken(ctx context.Context, accessJWS, refreshTokenID string) error {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	accessToken, err := s.tokenManager.ParseAccess(accessJWS)
	if err != nil {
		l.WarnContext(ctx, "parse access token", slogx.Error(err))
		return domain.ErrTokenInvalid
	}

	parsedRefreshTokenID, err := uuid.Parse(refreshTokenID)
	if err != nil {
		l.WarnContext(ctx, "invalid refresh token id")
		return domain.ErrTokenInvalid
	}

	return s.transactor.Single(ctx, func(ctx context.Context, executor sqlx.Executor) error {
		store := s.storeProvider.New(executor)
		if err := store.DeleteRefreshToken(ctx, accessToken.UserID, parsedRefreshTokenID); err != nil {
			if errors.Is(err, sqlx.ErrNotFound) {
				l.WarnContext(ctx, "delete refresh token from store", slogx.Error(err))
				return domain.ErrTokenNotFound
			}
			l.ErrorContext(ctx, "delete refresh token from store", slogx.Error(err))
			return err
		}
		return nil
	})
}

func (s *Service) DeleteUser(ctx context.Context, accessJWS, userID string) error {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	accessToken, err := s.tokenManager.ParseAccess(accessJWS)
	if err != nil {
		l.WarnContext(ctx, "parse access token", slogx.Error(err))
		return domain.ErrTokenInvalid
	}

	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return domain.ErrUserNotFound
	}
	if parsedUserID != accessToken.UserID {
		return domain.ErrUserNotFound
	}

	return s.transactor.Single(ctx, func(ctx context.Context, executor sqlx.Executor) error {
		store := s.storeProvider.New(executor)
		if err := store.DeleteUser(ctx, parsedUserID); err != nil {
			if errors.Is(err, sqlx.ErrNotFound) {
				l.WarnContext(ctx, "delete user from store", slogx.Error(err))
				return domain.ErrUserNotFound
			}
			l.ErrorContext(ctx, "delete user from store", slogx.Error(err))
			return err
		}
		return nil
	})
}
