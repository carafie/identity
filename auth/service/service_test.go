package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"
	"time"
	"uuid"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/auth/mailer"
	"github.com/carafie/identity/auth/store"
	"github.com/carafie/identity/internal/database"
	"github.com/carafie/identity/internal/logging"
	"github.com/carafie/identity/internal/mail"
)

var errTest = errors.New("expected test error")

type testStore struct {
	createOTPErr  error
	consumeOTP    *domain.OTP
	consumeOTPErr error
	deleteOTPErr  error

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

func (s testStore) CreateOTP(ctx context.Context, otp *domain.OTP) error {
	return s.createOTPErr
}

func (s testStore) ConsumeOTP(ctx context.Context, otpID uuid.UUID) (*domain.OTP, error) {
	return s.consumeOTP, s.consumeOTPErr
}

func (s testStore) DeleteOTP(ctx context.Context, otpID uuid.UUID) error {
	return s.deleteOTPErr
}

func (s testStore) GetUserByEmailOrCreate(ctx context.Context, user *domain.User) (*domain.User, error) {
	return s.getUserByEmailOrCreate, s.getUserByEmailOrCreateErr
}

func (s testStore) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	return s.deleteUserErr
}

func (s testStore) CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	return s.createRefreshTokenErr
}

func (s testStore) GetRefreshToken(ctx context.Context, userID, refreshTokenID uuid.UUID) (
	*domain.RefreshToken, error,
) {
	return s.getRefreshToken, s.getRefreshTokenErr
}

func (s testStore) ListRefreshTokens(ctx context.Context, userID uuid.UUID) ([]*domain.RefreshToken, error) {
	return s.listRefreshTokens, s.listRefreshTokensErr
}

func (s testStore) DeleteRefreshToken(ctx context.Context, userID, tokenID uuid.UUID) error {
	return s.deleteRefreshTokenErr
}

var _ store.Store = testStore{}

type testStoreFactory struct {
	store testStore
}

func (p testStoreFactory) New(executor database.Executor) store.Store {
	return p.store
}

var _ store.Factory = testStoreFactory{}

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
	atomicErr error
}

var _ database.Transactor = testTransactor{}

func (t testTransactor) Single(ctx context.Context, work database.Work) error {
	if err := work(ctx, nil); err != nil {
		return err
	}
	return t.singleErr
}

func (t testTransactor) Atomic(ctx context.Context, work database.Work) error {
	if err := work(ctx, nil); err != nil {
		return err
	}
	return t.atomicErr
}

func TestService_RequestOTP(t *testing.T) {
	tests := map[string]struct {
		storeFactory store.Factory
		mailer       mailer.Mailer
		transactor   database.Transactor
		email        string
		wantErr      error
	}{
		"invalid email": {
			storeFactory: testStoreFactory{testStore{}},
			mailer:       testMailer{},
			transactor:   testTransactor{},
			email:        "invalid",
			wantErr:      mail.ErrInvalid,
		},
		"transactor single error": {
			storeFactory: testStoreFactory{testStore{}},
			mailer:       testMailer{},
			transactor:   testTransactor{singleErr: errTest},
			email:        "otp@test",
			wantErr:      errTest,
		},
		"store create otp error": {
			storeFactory: testStoreFactory{testStore{createOTPErr: errTest}},
			mailer:       testMailer{},
			transactor:   testTransactor{},
			email:        "otp@test",
			wantErr:      errTest,
		},
		"mailer send otp request error": {
			storeFactory: testStoreFactory{testStore{}},
			mailer:       testMailer{sendOTPRequestErr: errTest},
			transactor:   testTransactor{},
			email:        "otp@test",
			wantErr:      errTest,
		},
		"success": {
			storeFactory: testStoreFactory{testStore{}},
			mailer:       testMailer{},
			transactor:   testTransactor{},
			email:        "otp@test",
			wantErr:      nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				StoreFactory:         test.storeFactory,
				Mailer:               test.mailer,
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         testJWTManager(t),
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
			})
			ctx := logging.NewContext(t.Context(), slog.New(slog.NewJSONHandler(t.Output(), nil)))
			_, gotErr := service.RequestOTP(ctx, test.email)
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
		storeFactory   store.Factory
		otpMaxAttempts int
		transactor     database.Transactor
		otpID          uuid.UUID
		code           string
		wantErr        error
	}{
		"invalid code": {
			storeFactory:   testStoreFactory{testStore{}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           "",
			wantErr:        domain.ErrCodeInvalid,
		},
		"transactor atomic error": {
			storeFactory:   testStoreFactory{testStore{consumeOTP: otp, getUserByEmailOrCreate: user}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{atomicErr: errTest},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"store consume otp error": {
			storeFactory:   testStoreFactory{testStore{consumeOTPErr: errTest}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"store consume otp not found error": {
			storeFactory:   testStoreFactory{testStore{consumeOTPErr: database.ErrNotFound}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        domain.ErrCodeExpired,
		},
		"code expired": {
			storeFactory:   testStoreFactory{testStore{consumeOTP: domain.NewOTP(email, -1)}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        domain.ErrCodeExpired,
		},
		"max attempts reached": {
			storeFactory:   testStoreFactory{testStore{consumeOTP: otp}},
			otpMaxAttempts: 0,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        domain.ErrCodeExpired,
		},
		"code mismatch": {
			storeFactory:   testStoreFactory{testStore{consumeOTP: otp}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(domain.NewCode()),
			wantErr:        domain.ErrCodeMismatched,
		},
		"delete otp store error": {
			storeFactory:   testStoreFactory{testStore{consumeOTP: otp, deleteOTPErr: errTest}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"get by email or create user store error": {
			storeFactory:   testStoreFactory{testStore{consumeOTP: otp, getUserByEmailOrCreateErr: errTest}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"create refresh token store error": {
			storeFactory: testStoreFactory{
				testStore{consumeOTP: otp, getUserByEmailOrCreate: user, createRefreshTokenErr: errTest},
			},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"success": {
			storeFactory:   testStoreFactory{testStore{consumeOTP: otp, getUserByEmailOrCreate: user}},
			otpMaxAttempts: 3,
			transactor:     testTransactor{},
			otpID:          otp.ID,
			code:           string(otp.Code),
			wantErr:        nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				StoreFactory:         test.storeFactory,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       test.otpMaxAttempts,
				TokenManager:         testJWTManager(t),
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
			})
			ctx := logging.NewContext(t.Context(), slog.New(slog.NewJSONHandler(t.Output(), nil)))
			_, _, gotErr := service.ConfirmOTP(ctx, test.otpID, test.code)
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
		storeFactory store.Factory
		transactor   database.Transactor
		refreshJWS   string
		wantErr      error
	}{
		"invalid refresh jws": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			refreshJWS:   "invalid",
			wantErr:      domain.ErrTokenInvalid,
		},
		"expired refresh token": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			refreshJWS:   expiredRefreshToken.JWS,
			wantErr:      domain.ErrTokenInvalid,
		},
		"invalid token kind": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			refreshJWS:   invalidKindToken.JWS,
			wantErr:      domain.ErrTokenInvalid,
		},
		"transactor single error": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{singleErr: errTest},
			refreshJWS:   refreshToken.JWS,
			wantErr:      errTest,
		},
		"store get refresh token error": {
			storeFactory: testStoreFactory{testStore{getRefreshTokenErr: errTest}},
			transactor:   testTransactor{},
			refreshJWS:   refreshToken.JWS,
			wantErr:      errTest,
		},
		"store get refresh token not found error": {
			storeFactory: testStoreFactory{testStore{getRefreshTokenErr: database.ErrNotFound}},
			transactor:   testTransactor{},
			refreshJWS:   refreshToken.JWS,
			wantErr:      domain.ErrTokenNotFound,
		},
		"success": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			refreshJWS:   refreshToken.JWS,
			wantErr:      nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				StoreFactory:         test.storeFactory,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         tokenManager,
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
			})
			ctx := logging.NewContext(t.Context(), slog.New(slog.NewJSONHandler(t.Output(), nil)))
			_, gotErr := service.RefreshAccessToken(ctx, test.refreshJWS)
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
		storeFactory store.Factory
		transactor   database.Transactor
		accessJWS    string
		wantErr      error
	}{
		"invalid access jws": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			accessJWS:    "invalid",
			wantErr:      domain.ErrTokenInvalid,
		},
		"expired access token": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			accessJWS:    expiredAccessToken.JWS,
			wantErr:      domain.ErrTokenInvalid,
		},
		"invalid token kind": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			accessJWS:    invalidKindToken.JWS,
			wantErr:      domain.ErrTokenInvalid,
		},
		"transactor single error": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{singleErr: errTest},
			accessJWS:    accessToken.JWS,
			wantErr:      errTest,
		},
		"store list refresh tokens error": {
			storeFactory: testStoreFactory{testStore{listRefreshTokensErr: errTest}},
			transactor:   testTransactor{},
			accessJWS:    accessToken.JWS,
			wantErr:      errTest,
		},
		"success": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			accessJWS:    accessToken.JWS,
			wantErr:      nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				StoreFactory:         test.storeFactory,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         tokenManager,
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
			})
			ctx := logging.NewContext(t.Context(), slog.New(slog.NewJSONHandler(t.Output(), nil)))
			_, gotErr := service.ListRefreshTokens(ctx, test.accessJWS)
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
		storeFactory   store.Factory
		transactor     database.Transactor
		accessJWS      string
		refreshTokenID uuid.UUID
		wantErr        error
	}{
		"invalid access jws": {
			storeFactory:   testStoreFactory{testStore{}},
			transactor:     testTransactor{},
			accessJWS:      "invalid",
			refreshTokenID: refreshToken.ID,
			wantErr:        domain.ErrTokenInvalid,
		},
		"expired access token": {
			storeFactory:   testStoreFactory{testStore{}},
			transactor:     testTransactor{},
			accessJWS:      expiredAccessToken.JWS,
			refreshTokenID: refreshToken.ID,
			wantErr:        domain.ErrTokenInvalid,
		},
		"invalid token kind": {
			storeFactory:   testStoreFactory{testStore{}},
			transactor:     testTransactor{},
			accessJWS:      invalidKindToken.JWS,
			refreshTokenID: refreshToken.ID,
			wantErr:        domain.ErrTokenInvalid,
		},
		"transactor single error": {
			storeFactory:   testStoreFactory{testStore{}},
			transactor:     testTransactor{singleErr: errTest},
			accessJWS:      accessToken.JWS,
			refreshTokenID: refreshToken.ID,
			wantErr:        errTest,
		},
		"store delete refresh token error": {
			storeFactory:   testStoreFactory{testStore{deleteRefreshTokenErr: errTest}},
			transactor:     testTransactor{},
			accessJWS:      accessToken.JWS,
			refreshTokenID: refreshToken.ID,
			wantErr:        errTest,
		},
		"success": {
			storeFactory:   testStoreFactory{testStore{}},
			transactor:     testTransactor{},
			accessJWS:      accessToken.JWS,
			refreshTokenID: refreshToken.ID,
			wantErr:        nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				StoreFactory:         test.storeFactory,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         tokenManager,
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
			})
			ctx := logging.NewContext(t.Context(), slog.New(slog.NewJSONHandler(t.Output(), nil)))
			gotErr := service.DeleteRefreshToken(ctx, test.accessJWS, test.refreshTokenID)
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
		storeFactory store.Factory
		transactor   database.Transactor
		accessJWS    string
		userID       uuid.UUID
		wantErr      error
	}{
		"invalid access jws": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			accessJWS:    "invalid",
			userID:       user.ID,
			wantErr:      domain.ErrTokenInvalid,
		},
		"expired access token": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			accessJWS:    expiredAccessToken.JWS,
			userID:       user.ID,
			wantErr:      domain.ErrTokenInvalid,
		},
		"invalid token kind": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			accessJWS:    invalidKindToken.JWS,
			userID:       user.ID,
			wantErr:      domain.ErrTokenInvalid,
		},
		"transactor single error": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{singleErr: errTest},
			accessJWS:    accessToken.JWS,
			userID:       user.ID,
			wantErr:      errTest,
		},
		"store delete user error": {
			storeFactory: testStoreFactory{testStore{deleteUserErr: errTest}},
			transactor:   testTransactor{},
			accessJWS:    accessToken.JWS,
			userID:       user.ID,
			wantErr:      errTest,
		},
		"success": {
			storeFactory: testStoreFactory{testStore{}},
			transactor:   testTransactor{},
			accessJWS:    accessToken.JWS,
			userID:       user.ID,
			wantErr:      nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(&Params{
				StoreFactory:         test.storeFactory,
				Mailer:               testMailer{},
				OTPDuration:          15 * time.Minute,
				OTPMaxAttempts:       3,
				TokenManager:         tokenManager,
				TokenAccessDuration:  1 * time.Hour,
				TokenRefreshDuration: 90 * 24 * time.Hour,
				Transactor:           test.transactor,
			})
			ctx := logging.NewContext(t.Context(), slog.New(slog.NewJSONHandler(t.Output(), nil)))
			gotErr := service.DeleteUser(ctx, test.accessJWS, test.userID)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.DeleteUser(...), gotErr=%q, wantErr=%q",
					gotErr, test.wantErr,
				)
			}
		})
	}
}
