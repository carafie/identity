package otp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/carafie/identity/platform/jwt"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/sqlx"
	"github.com/carafie/identity/platform/uuid"
	"github.com/carafie/identity/service/token"
	"github.com/carafie/identity/service/user"
)

type testOTPStore struct {
	createErr  error
	consume    *OTP
	consumeErr error
}

func (s testOTPStore) Create(ctx context.Context, executor sqlx.Executor, otp *OTP) error {
	return s.createErr
}

func (s testOTPStore) Consume(ctx context.Context, executor sqlx.Executor, id uuid.UUID) (*OTP, error) {
	return s.consume, s.consumeErr
}

type testOTPMailer struct {
	sendRequestErr error
}

func (m testOTPMailer) SendRequest(ctx context.Context, otp *OTP) error {
	return m.sendRequestErr
}

type testUserStore struct {
	getByEmailOrCreate    *user.User
	getByEmailOrCreateErr error
}

func (s testUserStore) GetByEmailOrCreate(
	ctx context.Context, executor sqlx.Executor, user *user.User,
) (*user.User, error) {
	return s.getByEmailOrCreate, s.getByEmailOrCreateErr
}

type testTokenStore struct {
	createRefreshErr error
}

func (s testTokenStore) CreateRefresh(ctx context.Context, executor sqlx.Executor, token token.Refresh) error {
	return s.createRefreshErr
}

var testJWTManager = func(t *testing.T) *jwt.Manager {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return jwt.NewManager(publicKey, privateKey)
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

var errTest = errors.New("expected test error")

func TestService_Request(t *testing.T) {
	tests := map[string]struct {
		otpStore   Store
		otpMailer  Mailer
		transactor sqlx.Transactor
		email      string
		wantErr    error
	}{
		"invalid email": {
			otpStore:   testOTPStore{},
			otpMailer:  testOTPMailer{},
			transactor: testTransactor{},
			email:      "invalid",
			wantErr:    mail.ErrInvalid,
		},
		"transactor single error": {
			otpStore:   testOTPStore{},
			otpMailer:  testOTPMailer{},
			transactor: testTransactor{singleErr: errTest},
			email:      "otp@test",
			wantErr:    errTest,
		},
		"otp store create error": {
			otpStore:   testOTPStore{createErr: errTest},
			otpMailer:  testOTPMailer{},
			transactor: testTransactor{},
			email:      "otp@test",
			wantErr:    errTest,
		},
		"otp mailer send request error": {
			otpStore:   testOTPStore{},
			otpMailer:  testOTPMailer{sendRequestErr: errTest},
			transactor: testTransactor{},
			email:      "otp@test",
			wantErr:    errTest,
		},
		"success": {
			otpStore:   testOTPStore{},
			otpMailer:  testOTPMailer{},
			transactor: testTransactor{},
			email:      "otp@test",
			wantErr:    nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := NewService(&ServiceParams{
				OTPStore:           test.otpStore,
				OTPMailer:          test.otpMailer,
				OTPDuration:        15 * time.Minute,
				OTPMaxAttempts:     3,
				UserStore:          testUserStore{},
				TokenStore:         testTokenStore{},
				JWTManager:         testJWTManager(t),
				JWTAccessDuration:  1 * time.Hour,
				JWTRefreshDuration: 90 * 24 * time.Hour,
				Transactor:         test.transactor,
				Logger:             slog.New(slog.NewJSONHandler(t.Output(), nil)),
			})
			_, gotErr := service.Request(t.Context(), test.email)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.Request(..., %q), gotErr=%q, wantErr=%q",
					test.email, gotErr, test.wantErr,
				)
			}
		})
	}
}

func TestService_Confirm(t *testing.T) {
	email, err := mail.Parse("otp@test")
	if err != nil {
		t.Fatalf("failed to parse email: %v", err)
	}
	otp := New(email, 1*time.Hour)
	usr := user.New(email)

	tests := map[string]struct {
		otpStore       Store
		otpMaxAttempts int
		userStore      user.Store
		tokenStore     token.Store
		transactor     sqlx.Transactor
		otpID          string
		code           string
		wantErr        error
	}{
		"invalid otp id": {
			otpStore:       testOTPStore{},
			otpMaxAttempts: 3,
			userStore:      testUserStore{},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          "",
			code:           string(otp.Code),
			wantErr:        uuid.ErrInvalid,
		},
		"invalid code": {
			otpStore:       testOTPStore{},
			otpMaxAttempts: 3,
			userStore:      testUserStore{},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           "",
			wantErr:        ErrCodeInvalid,
		},
		"transactor atomic error": {
			otpStore:       testOTPStore{consume: otp},
			otpMaxAttempts: 3,
			userStore:      testUserStore{getByEmailOrCreate: usr},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{atomicErr: errTest},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"otp store consume error": {
			otpStore:       testOTPStore{consumeErr: errTest},
			otpMaxAttempts: 3,
			userStore:      testUserStore{},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"otp store consume not found error": {
			otpStore:       testOTPStore{consumeErr: sqlx.ErrNotFound},
			otpMaxAttempts: 3,
			userStore:      testUserStore{},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        ErrCodeExpired,
		},
		"code expired": {
			otpStore:       testOTPStore{consume: New(email, -1)},
			otpMaxAttempts: 3,
			userStore:      testUserStore{},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        ErrCodeExpired,
		},
		"max attempts reached": {
			otpStore:       testOTPStore{consume: otp},
			otpMaxAttempts: 0,
			userStore:      testUserStore{},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        ErrCodeExpired,
		},
		"code mismatch": {
			otpStore:       testOTPStore{consume: otp},
			otpMaxAttempts: 3,
			userStore:      testUserStore{},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(NewCode()),
			wantErr:        ErrCodeMismatch,
		},
		"get by email or create user store error": {
			otpStore:       testOTPStore{consume: otp},
			otpMaxAttempts: 3,
			userStore:      testUserStore{getByEmailOrCreateErr: errTest},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"create refresh token store error": {
			otpStore:       testOTPStore{consume: otp},
			otpMaxAttempts: 3,
			userStore:      testUserStore{getByEmailOrCreate: usr},
			tokenStore:     testTokenStore{createRefreshErr: errTest},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        errTest,
		},
		"success": {
			otpStore:       testOTPStore{consume: otp},
			otpMaxAttempts: 3,
			userStore:      testUserStore{getByEmailOrCreate: usr},
			tokenStore:     testTokenStore{},
			transactor:     testTransactor{},
			otpID:          otp.ID.String(),
			code:           string(otp.Code),
			wantErr:        nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := NewService(&ServiceParams{
				OTPStore:           test.otpStore,
				OTPMailer:          testOTPMailer{},
				OTPDuration:        15 * time.Minute,
				OTPMaxAttempts:     test.otpMaxAttempts,
				UserStore:          test.userStore,
				TokenStore:         test.tokenStore,
				JWTManager:         testJWTManager(t),
				JWTAccessDuration:  1 * time.Hour,
				JWTRefreshDuration: 90 * 24 * time.Hour,
				Transactor:         test.transactor,
				Logger:             slog.New(slog.NewJSONHandler(t.Output(), nil)),
			})
			_, _, gotErr := service.Confirm(t.Context(), test.otpID, test.code)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf(
					"Service.Confirm(..., ..., %q), gotErr=%q, wantErr=%q",
					test.code, gotErr, test.wantErr,
				)
			}
		})
	}
}
