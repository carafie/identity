package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/auth/mailer"
	"github.com/carafie/identity/auth/store"
	"github.com/carafie/identity/internal/database"
	"github.com/carafie/identity/internal/mail"
	"github.com/carafie/identity/internal/requestid"
	"github.com/carafie/identity/internal/slogx"
	"github.com/carafie/identity/internal/uuid"
)

type Service struct {
	storeFactory store.Factory
	mailer       mailer.Mailer

	otpDuration    time.Duration
	otpMaxAttempts int

	tokenManager         *domain.TokenManager
	tokenAccessDuration  time.Duration
	tokenRefreshDuration time.Duration

	transactor database.Transactor
	logger     *slog.Logger
}

type Params struct {
	StoreFactory store.Factory
	Mailer       mailer.Mailer

	OTPDuration    time.Duration
	OTPMaxAttempts int

	TokenManager         *domain.TokenManager
	TokenAccessDuration  time.Duration
	TokenRefreshDuration time.Duration

	Transactor database.Transactor
	Logger     *slog.Logger
}

func New(params *Params) *Service {
	if params.StoreFactory == nil {
		panic("service.New: store.Factory cannot be nil")
	}
	if params.Mailer == nil {
		panic("service.New: mailer.Mailer cannot be nil")
	}
	if params.TokenManager == nil {
		panic("service.New: *domain.TokenManager cannot be nil")
	}
	if params.Transactor == nil {
		panic("service.New: database.Transactor cannot be nil")
	}
	if params.Logger == nil {
		params.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		storeFactory: params.StoreFactory,
		mailer:       params.Mailer,

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

	err = s.transactor.Single(ctx, func(ctx context.Context, executor database.Executor) error {
		store := s.storeFactory.New(executor)
		if err := store.CreateOTP(ctx, otp); err != nil {
			return fmt.Errorf("failed to create otp: %w", err)
		}
		return nil
	})
	if err != nil {
		l.ErrorContext(ctx, "database transaction", slogx.Error(err))
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
		safeErr      error
	)
	err = s.transactor.Atomic(ctx, func(ctx context.Context, executor database.Executor) error {
		store := s.storeFactory.New(executor)

		otp, err := store.ConsumeOTP(ctx, parsedOTPID)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				err = domain.ErrCodeExpired
			}
			return fmt.Errorf("failed to consume otp: %w", err)
		}
		if err := otp.Validate(parsedCode, s.otpMaxAttempts); err != nil {
			// Return no error so the transaction commits and increases the attempts counter.
			safeErr = err
			return nil
		}

		if err := store.DeleteOTP(ctx, otp.ID); err != nil {
			return fmt.Errorf("failed to delete otp: %w", err)
		}

		user, err := store.GetUserByEmailOrCreate(ctx, domain.NewUser(otp.Email))
		if err != nil {
			return fmt.Errorf("failed to get user by email or create: %w", err)
		}

		access := domain.NewAccessToken(user.ID, user.Email, s.tokenAccessDuration)
		if err := s.tokenManager.SignAccess(access); err != nil {
			return fmt.Errorf("failed to sign access token: %w", err)
		}
		refresh := domain.NewRefreshToken(user.ID, user.Email, s.tokenRefreshDuration)
		if err := s.tokenManager.SignRefresh(refresh); err != nil {
			return fmt.Errorf("failed to sign refresh token: %w", err)
		}
		if err := store.CreateRefreshToken(ctx, refresh); err != nil {
			return fmt.Errorf("failed to create refresh token: %w", err)
		}
		accessToken = access
		refreshToken = refresh

		return nil
	})
	if err != nil {
		l.ErrorContext(ctx, "database transaction", slogx.Error(err))
		return nil, nil, err
	}
	return accessToken, refreshToken, safeErr
}

func (s *Service) RefreshAccessToken(ctx context.Context, refreshJWS string) (*domain.AccessToken, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	refreshToken, err := s.tokenManager.ParseRefresh(refreshJWS)
	if err != nil {
		l.WarnContext(ctx, "parse refresh token", slogx.Error(err))
		return nil, domain.ErrTokenInvalid
	}

	err = s.transactor.Single(ctx, func(ctx context.Context, executor database.Executor) error {
		store := s.storeFactory.New(executor)
		if _, err := store.GetRefreshToken(ctx, refreshToken.UserID, refreshToken.ID); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				err = domain.ErrTokenNotFound
			}
			return fmt.Errorf("failed to get refresh token: %w", err)
		}
		return nil
	})
	if err != nil {
		l.ErrorContext(ctx, "database transaction", slogx.Error(err))
		return nil, err
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

	err = s.transactor.Single(ctx, func(ctx context.Context, executor database.Executor) error {
		store := s.storeFactory.New(executor)
		tokens, err := store.ListRefreshTokens(ctx, accessToken.UserID)
		if err != nil {
			return fmt.Errorf("failed to list refresh tokens: %w", err)
		}
		refreshTokens = tokens
		return nil
	})
	if err != nil {
		l.ErrorContext(ctx, "database transaction", slogx.Error(err))
		return nil, err
	}

	return refreshTokens, nil
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

	err = s.transactor.Single(ctx, func(ctx context.Context, executor database.Executor) error {
		store := s.storeFactory.New(executor)
		if err := store.DeleteRefreshToken(ctx, accessToken.UserID, parsedRefreshTokenID); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				err = domain.ErrTokenNotFound
			}
			return fmt.Errorf("failed to delete refresh token: %w", err)
		}
		return nil
	})
	if err != nil {
		l.ErrorContext(ctx, "database transaction", slogx.Error(err))
		return err
	}

	return nil
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

	err = s.transactor.Single(ctx, func(ctx context.Context, executor database.Executor) error {
		store := s.storeFactory.New(executor)
		if err := store.DeleteUser(ctx, parsedUserID); err != nil {
			if errors.Is(err, database.ErrNotFound) {
				err = domain.ErrUserNotFound
			}
			return fmt.Errorf("failed to delete user: %w", err)
		}
		return nil
	})
	if err != nil {
		l.ErrorContext(ctx, "database transaction", slogx.Error(err))
		return err
	}

	return nil
}
