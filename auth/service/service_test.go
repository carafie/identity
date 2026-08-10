package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/auth/mailer"
	"github.com/carafie/identity/auth/store"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/sqlx"
	"github.com/carafie/identity/platform/uuid"
)

var errTest = errors.New("expected test error")

type testStore struct {
	createOTPErr  error
	consumeOTP    *domain.OTP
	consumeOTPErr error

	getUserByEmailOrCreate    *domain.User
	getUserByEmailOrCreateErr error
	deleteUserErr             error

	createRefreshTokenErr error
	getRefreshToken       *domain.RefreshToken
	getRefreshTokenErr    error
	listRefreshTokens     []*domain.RefreshToken
	listRefreshTokensErr  error
	deleteRefreshTokenErr error
}

func (s testStore) CreateOTP(ctx context.Context, executor sqlx.Executor, otp *domain.OTP) error {
	return s.createOTPErr
}

func (s testStore) ConsumeOTP(ctx context.Context, executor sqlx.Executor, otpID uuid.UUID) (*domain.OTP, error) {
	return s.consumeOTP, s.consumeOTPErr
}

func (s testStore) GetUserByEmailOrCreate(
	ctx context.Context, executor sqlx.Executor, user *domain.User,
) (*domain.User, error) {
	return s.getUserByEmailOrCreate, s.getUserByEmailOrCreateErr
}

func (s testStore) DeleteUser(ctx context.Context, executor sqlx.Executor, userID uuid.UUID) error {
	return s.deleteUserErr
}

func (s testStore) CreateRefreshToken(ctx context.Context, executor sqlx.Executor, token *domain.RefreshToken) error {
	return s.createRefreshTokenErr
}

func (s testStore) GetRefreshToken(ctx context.Context, executor sqlx.Executor, refreshTokenID uuid.UUID) (
	*domain.RefreshToken, error,
) {
	return s.getRefreshToken, s.getRefreshTokenErr
}

func (s testStore) ListRefreshTokens(
	ctx context.Context, executor sqlx.Executor, userID uuid.UUID,
) ([]*domain.RefreshToken, error) {
	return s.listRefreshTokens, s.listRefreshTokensErr
}

func (s testStore) DeleteRefreshToken(ctx context.Context, executor sqlx.Executor, userID, tokenID uuid.UUID) error {
	return s.deleteRefreshTokenErr
}

var _ store.Store = testStore{}

type testMailer struct {
	sendOTPRequestErr error
}

func (m testMailer) SendOTPRequest(ctx context.Context, otp *domain.OTP) error {
	return m.sendOTPRequestErr
}

var _ mailer.Mailer = testMailer{}

var testJWTManager = func(t *testing.T) *domain.TokenManager {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return domain.NewTokenManager(publicKey, privateKey)
}

type testTransactor struct {
	singleErr error
	atomic    sqlx.TCL
	atomicErr error
}

func (t testTransactor) Single(ctx context.Context, work sqlx.TransactorSingleWork) error {
	if err := work(ctx, nil); err != nil {
		return err
	}
	return t.singleErr
}

func (t testTransactor) Atomic(ctx context.Context, work sqlx.TransactorAtomicWork) error {
	if _, err := work(ctx, nil); err != nil {
		return err
	}
	return t.atomicErr
}

func TestService_RequestOTP(t *testing.T) {
	tests := map[string]struct {
		store      store.Store
		mailer     mailer.Mailer
		transactor sqlx.Transactor
		email      string
		wantErr    error
	}{
		"invalid email": {
			store:      testStore{},
			mailer:     testMailer{},
			transactor: testTransactor{},
			email:      "invalid",
			wantErr:    mail.ErrInvalid,
		},
		"transactor single error": {
			store:      testStore{},
			mailer:     testMailer{},
			transactor: testTransactor{singleErr: errTest},
			email:      "otp@test",
			wantErr:    errTest,
		},
		"store create otp error": {
			store:      testStore{createOTPErr: errTest},
			mailer:     testMailer{},
			transactor: testTransactor{},
			email:      "otp@test",
			wantErr:    errTest,
		},
		"mailer send otp request error": {
			store:      testStore{},
			mailer:     testMailer{sendOTPRequestErr: errTest},
			transactor: testTransactor{},
			email:      "otp@test",
			wantErr:    errTest,
		},
		"success": {
			store:      testStore{},
			mailer:     testMailer{},
			transactor: testTransactor{},
			email:      "otp@test",
			wantErr:    nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				Store:                test.store,
				Mailer:               test.mailer,
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         testJWTManager(t),
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
				Logger:               slog.New(slog.NewJSONHandler(t.Output(), nil)),
			})
			_, gotErr := service.RequestOTP(t.Context(), test.email)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.Request(..., %q), gotErr=%q, wantErr=%q",
					test.email, gotErr, test.wantErr,
				)
			}
		})
	}
}

func TestService_ConfirmOTP(t *testing.T) {
	email, err := mail.Parse("otp@test")
	if err != nil {
		t.Fatalf("failed to parse email: %v", err)
	}
	otp := domain.NewOTP(email, 1*time.Hour)
	user := domain.NewUser(email)

	tests := map[string]struct {
		store          store.Store
		otpMaxAttempts int
		transactor     sqlx.Transactor
		otpID          string
		code           string
		wantErr        error
	}{
		"invalid otp id": {
			store:          testStore{},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          "",
			code:           string(otp.Code),
			wantErr:        uuid.ErrInvalid,
		},
		"invalid code": {
			store:          testStore{},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           "",
			wantErr:        domain.ErrCodeInvalid,
		},
		"transactor atomic error": {
			store:          testStore{consumeOTP: otp, getUserByEmailOrCreate: user},
			otpMaxAttempts: 3,
			transactor:     testTransactor{atomicErr: errTest},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"store consume otp error": {
			store:          testStore{consumeOTPErr: errTest},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"store consume otp not found error": {
			store:          testStore{consumeOTPErr: sqlx.ErrNotFound},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        domain.ErrCodeExpired,
		},
		"code expired": {
			store:          testStore{consumeOTP: domain.NewOTP(email, -1)},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        domain.ErrCodeExpired,
		},
		"max attempts reached": {
			store:          testStore{consumeOTP: otp},
			otpMaxAttempts: 0,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        domain.ErrCodeExpired,
		},
		"code mismatch": {
			store:          testStore{consumeOTP: otp},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(domain.NewCode()),
			wantErr:        domain.ErrCodeMismatched,
		},
		"get by email or create user store error": {
			store:          testStore{consumeOTP: otp, getUserByEmailOrCreateErr: errTest},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"create refresh token store error": {
			store:          testStore{consumeOTP: otp, getUserByEmailOrCreate: user, createRefreshTokenErr: errTest},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"success": {
			store:          testStore{consumeOTP: otp, getUserByEmailOrCreate: user},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				Store:                test.store,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       test.otpMaxAttempts,
				TokenManager:         testJWTManager(t),
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
				Logger:               slog.New(slog.NewJSONHandler(t.Output(), nil)),
			})
			_, _, gotErr := service.ConfirmOTP(t.Context(), test.otpID, test.code)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.Confirm(..., ..., %q), gotErr=%q, wantErr=%q",
					test.code, gotErr, test.wantErr,
				)
			}
		})
	}
}

func TestService_RefreshAccessToken(t *testing.T) {
	tokenManager := testJWTManager(t)
	user := domain.NewUser("token@test")

	refreshToken := domain.NewRefreshToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignRefresh(refreshToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	expiredRefreshToken := domain.NewRefreshToken(user.ID, user.Email, -time.Hour)
	if err := tokenManager.SignRefresh(expiredRefreshToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	invalidKindToken := domain.NewAccessToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignAccess(invalidKindToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	tests := map[string]struct {
		store      store.Store
		transactor sqlx.Transactor
		refreshJWS string
		wantErr    error
	}{
		"invalid refresh jws": {
			store:      testStore{},
			transactor: testTransactor{},
			refreshJWS: "invalid",
			wantErr:    domain.ErrTokenInvalid,
		},
		"expired refresh token": {
			store:      testStore{},
			transactor: testTransactor{},
			refreshJWS: expiredRefreshToken.JWS,
			wantErr:    domain.ErrTokenInvalid,
		},
		"invalid token kind": {
			store:      testStore{},
			transactor: testTransactor{},
			refreshJWS: invalidKindToken.JWS,
			wantErr:    domain.ErrTokenInvalid,
		},
		"transactor single error": {
			store:      testStore{},
			transactor: testTransactor{singleErr: errTest},
			refreshJWS: refreshToken.JWS,
			wantErr:    errTest,
		},
		"store get refresh token error": {
			store:      testStore{getRefreshTokenErr: errTest},
			transactor: testTransactor{},
			refreshJWS: refreshToken.JWS,
			wantErr:    errTest,
		},
		"store get refresh token not found error": {
			store:      testStore{getRefreshTokenErr: sqlx.ErrNotFound},
			transactor: testTransactor{},
			refreshJWS: refreshToken.JWS,
			wantErr:    domain.ErrTokenNotFound,
		},
		"success": {
			store:      testStore{},
			transactor: testTransactor{},
			refreshJWS: refreshToken.JWS,
			wantErr:    nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				Store:                test.store,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         tokenManager,
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
				Logger:               slog.New(slog.NewJSONHandler(t.Output(), nil)),
			})
			_, gotErr := service.RefreshAccessToken(t.Context(), test.refreshJWS)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.RefreshAccessToken(...), gotErr=%q, wantErr=%q",
					gotErr, test.wantErr,
				)
			}
		})
	}
}

func TestService_ListRefreshTokens(t *testing.T) {
	tokenManager := testJWTManager(t)
	user := domain.NewUser("token@test")

	accessToken := domain.NewAccessToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignAccess(accessToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	expiredAccessToken := domain.NewAccessToken(user.ID, user.Email, -time.Hour)
	if err := tokenManager.SignAccess(expiredAccessToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	invalidKindToken := domain.NewRefreshToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignRefresh(invalidKindToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	tests := map[string]struct {
		store      store.Store
		transactor sqlx.Transactor
		accessJWS  string
		wantErr    error
	}{
		"invalid access jws": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  "invalid",
			wantErr:    domain.ErrTokenInvalid,
		},
		"expired access token": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  expiredAccessToken.JWS,
			wantErr:    domain.ErrTokenInvalid,
		},
		"invalid token kind": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  invalidKindToken.JWS,
			wantErr:    domain.ErrTokenInvalid,
		},
		"transactor single error": {
			store:      testStore{},
			transactor: testTransactor{singleErr: errTest},
			accessJWS:  accessToken.JWS,
			wantErr:    errTest,
		},
		"store list refresh tokens error": {
			store:      testStore{listRefreshTokensErr: errTest},
			transactor: testTransactor{},
			accessJWS:  accessToken.JWS,
			wantErr:    errTest,
		},
		"success": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  accessToken.JWS,
			wantErr:    nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				Store:                test.store,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         tokenManager,
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
				Logger:               slog.New(slog.NewJSONHandler(t.Output(), nil)),
			})
			_, gotErr := service.ListRefreshTokens(t.Context(), test.accessJWS)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.ListRefreshTokens(...), gotErr=%q, wantErr=%q",
					gotErr, test.wantErr,
				)
			}
		})
	}
}

func TestService_DeleteRefreshToken(t *testing.T) {
	tokenManager := testJWTManager(t)
	user := domain.NewUser("token@test")

	refreshToken := domain.NewRefreshToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignRefresh(refreshToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	accessToken := domain.NewAccessToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignAccess(accessToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	expiredAccessToken := domain.NewAccessToken(user.ID, user.Email, -time.Hour)
	if err := tokenManager.SignAccess(expiredAccessToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	invalidKindToken := domain.NewRefreshToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignRefresh(invalidKindToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	tests := map[string]struct {
		store          store.Store
		transactor     sqlx.Transactor
		accessJWS      string
		refreshTokenID string
		wantErr        error
	}{
		"invalid access jws": {
			store:          testStore{},
			transactor:     testTransactor{},
			accessJWS:      "invalid",
			refreshTokenID: refreshToken.ID.String(),
			wantErr:        domain.ErrTokenInvalid,
		},
		"expired access token": {
			store:          testStore{},
			transactor:     testTransactor{},
			accessJWS:      expiredAccessToken.JWS,
			refreshTokenID: refreshToken.ID.String(),
			wantErr:        domain.ErrTokenInvalid,
		},
		"invalid token kind": {
			store:          testStore{},
			transactor:     testTransactor{},
			accessJWS:      invalidKindToken.JWS,
			refreshTokenID: refreshToken.ID.String(),
			wantErr:        domain.ErrTokenInvalid,
		},
		"invalid refresh token id": {
			store:          testStore{},
			transactor:     testTransactor{},
			accessJWS:      invalidKindToken.JWS,
			refreshTokenID: "invalid",
			wantErr:        domain.ErrTokenInvalid,
		},
		"transactor single error": {
			store:          testStore{},
			transactor:     testTransactor{singleErr: errTest},
			accessJWS:      accessToken.JWS,
			refreshTokenID: refreshToken.ID.String(),
			wantErr:        errTest,
		},
		"store delete refresh token error": {
			store:          testStore{deleteRefreshTokenErr: errTest},
			transactor:     testTransactor{},
			accessJWS:      accessToken.JWS,
			refreshTokenID: refreshToken.ID.String(),
			wantErr:        errTest,
		},
		"success": {
			store:          testStore{},
			transactor:     testTransactor{},
			accessJWS:      accessToken.JWS,
			refreshTokenID: refreshToken.ID.String(),
			wantErr:        nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				Store:                test.store,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         tokenManager,
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
				Logger:               slog.New(slog.NewJSONHandler(t.Output(), nil)),
			})
			gotErr := service.DeleteRefreshToken(t.Context(), test.accessJWS, test.refreshTokenID)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.DeleteRefreshToken(...), gotErr=%q, wantErr=%q",
					gotErr, test.wantErr,
				)
			}
		})
	}
}

func TestService_DeleteUser(t *testing.T) {
	tokenManager := testJWTManager(t)
	user := domain.NewUser("token@test")

	accessToken := domain.NewAccessToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignAccess(accessToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	expiredAccessToken := domain.NewAccessToken(user.ID, user.Email, -time.Hour)
	if err := tokenManager.SignAccess(expiredAccessToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	invalidKindToken := domain.NewRefreshToken(user.ID, user.Email, time.Hour)
	if err := tokenManager.SignRefresh(invalidKindToken); err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	tests := map[string]struct {
		store      store.Store
		transactor sqlx.Transactor
		accessJWS  string
		userID     string
		wantErr    error
	}{
		"invalid access jws": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  "invalid",
			userID:     user.ID.String(),
			wantErr:    domain.ErrTokenInvalid,
		},
		"expired access token": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  expiredAccessToken.JWS,
			userID:     user.ID.String(),
			wantErr:    domain.ErrTokenInvalid,
		},
		"invalid token kind": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  invalidKindToken.JWS,
			userID:     user.ID.String(),
			wantErr:    domain.ErrTokenInvalid,
		},
		"invalid user id": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  invalidKindToken.JWS,
			userID:     "invalid",
			wantErr:    domain.ErrTokenInvalid,
		},
		"transactor single error": {
			store:      testStore{},
			transactor: testTransactor{singleErr: errTest},
			accessJWS:  accessToken.JWS,
			userID:     user.ID.String(),
			wantErr:    errTest,
		},
		"store delete user error": {
			store:      testStore{deleteUserErr: errTest},
			transactor: testTransactor{},
			accessJWS:  accessToken.JWS,
			userID:     user.ID.String(),
			wantErr:    errTest,
		},
		"success": {
			store:      testStore{},
			transactor: testTransactor{},
			accessJWS:  accessToken.JWS,
			userID:     user.ID.String(),
			wantErr:    nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				Store:                test.store,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         tokenManager,
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
				Logger:               slog.New(slog.NewJSONHandler(t.Output(), nil)),
			})
			gotErr := service.DeleteUser(t.Context(), test.accessJWS, test.userID)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.DeleteUser(...), gotErr=%q, wantErr=%q",
					gotErr, test.wantErr,
				)
			}
		})
	}
}
