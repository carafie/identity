package otp

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/carafie/identity/platform/jwt"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/requestid"
	"github.com/carafie/identity/platform/slogx"
	"github.com/carafie/identity/platform/sqlx"
	"github.com/carafie/identity/platform/uuid"
	"github.com/carafie/identity/service/token"
	"github.com/carafie/identity/service/user"
)

var (
	ErrCodeMismatch = errors.New("code mismatch")
	ErrCodeExpired  = errors.New("code is expired")
)

type Service struct {
	otpStore       Store
	otpMailer      Mailer
	otpDuration    time.Duration
	otpMaxAttempts int

	userStore user.Store

	tokenStore token.Store

	jwtManager         *jwt.Manager
	jwtAccessDuration  time.Duration
	jwtRefreshDuration time.Duration

	transactor sqlx.Transactor
	logger     *slog.Logger
}

type ServiceParams struct {
	OTPStore       Store
	OTPMailer      Mailer
	OTPDuration    time.Duration
	OTPMaxAttempts int

	UserStore user.Store

	TokenStore token.Store

	JWTManager         *jwt.Manager
	JWTAccessDuration  time.Duration
	JWTRefreshDuration time.Duration

	Transactor sqlx.Transactor
	Logger     *slog.Logger
}

func NewService(params *ServiceParams) *Service {
	if params.OTPStore == nil {
		panic("otp store cannot be nil")
	}
	if params.OTPMailer == nil {
		panic("otp mailer cannot be nil")
	}
	if params.UserStore == nil {
		panic("user store cannot be nil")
	}
	if params.TokenStore == nil {
		panic("token store cannot be nil")
	}
	if params.JWTManager == nil {
		panic("jwt manager cannot be nil")
	}
	if params.Transactor == nil {
		panic("transactor cannot be nil")
	}
	if params.Logger == nil {
		params.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		otpStore:       params.OTPStore,
		otpMailer:      params.OTPMailer,
		otpDuration:    params.OTPDuration,
		otpMaxAttempts: params.OTPMaxAttempts,

		userStore: params.UserStore,

		tokenStore: params.TokenStore,

		jwtManager:         params.JWTManager,
		jwtAccessDuration:  params.JWTAccessDuration,
		jwtRefreshDuration: params.JWTRefreshDuration,

		transactor: params.Transactor,
		logger:     params.Logger,
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

func (s *Service) Confirm(ctx context.Context, otpID, code string) (token.Access, token.Refresh, error) {
	l := s.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	id, err := uuid.Parse(otpID)
	if err != nil {
		l.WarnContext(ctx, "parse otp id", slogx.Error(err))
		return "", token.Refresh{}, err
	}
	parsedCode, err := ParseCode(code)
	if err != nil {
		l.WarnContext(ctx, "parse otp code", slogx.Error(err))
		return "", token.Refresh{}, err
	}

	var (
		access  token.Access
		refresh token.Refresh
	)
	err = s.transactor.Atomic(ctx, func(ctx context.Context, executor sqlx.Executor) (sqlx.TCL, error) {
		otp, err := s.otpStore.Consume(ctx, executor, id)
		if err != nil {
			if errors.Is(err, sqlx.ErrNotFound) {
				l.WarnContext(ctx, "consume otp in store", slogx.Error(err))
				return sqlx.Rollback, ErrCodeExpired
			}
			l.ErrorContext(ctx, "consume otp in store", slogx.Error(err))
			return sqlx.Rollback, err
		}
		if err := otp.Validate(parsedCode, s.otpMaxAttempts); err != nil {
			if errors.Is(err, ErrCodeMismatch) {
				return sqlx.Commit, err
			}
			return sqlx.Rollback, err
		}

		usr, err := s.userStore.GetByEmailOrCreate(ctx, executor, user.New(otp.Email))
		if err != nil {
			l.ErrorContext(ctx, "get user by email or create in store", slogx.Error(err))
			return sqlx.Rollback, err
		}

		innerAccess, innerRefresh, err := s.issueTokens(usr)
		if err != nil {
			l.ErrorContext(ctx, "issue tokens", slogx.Error(err))
			return sqlx.Rollback, err
		}
		if err := s.tokenStore.CreateRefresh(ctx, executor, innerRefresh); err != nil {
			l.ErrorContext(ctx, "create refresh token in store", slogx.Error(err))
			return sqlx.Rollback, err
		}
		access = innerAccess
		refresh = innerRefresh

		return sqlx.Commit, nil
	})
	return access, refresh, err
}

func (s *Service) issueTokens(usr *user.User) (token.Access, token.Refresh, error) {
	access, err := s.jwtManager.Sign(jwt.NewTokenFields(usr.ID, usr.Email, jwt.KindAccess, s.jwtAccessDuration))
	if err != nil {
		return "", token.Refresh{}, err
	}

	refreshFields := jwt.NewTokenFields(usr.ID, usr.Email, jwt.KindRefresh, s.jwtRefreshDuration)
	refreshToken, err := s.jwtManager.Sign(refreshFields)
	if err != nil {
		return "", token.Refresh{}, err
	}
	refresh := token.NewRefresh(
		refreshToken, refreshFields.ID, refreshFields.UserID, time.Now(), refreshFields.ExpiresAt,
	)

	return access, refresh, nil
}
