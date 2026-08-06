package otp

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/sqlx"
)

type testOTPStore struct {
	createErr error
}

func (s testOTPStore) Create(ctx context.Context, executor sqlx.Executor, otp *OTP) error {
	return s.createErr
}

type testOTPMailer struct {
	sendRequestErr error
}

func (m testOTPMailer) SendRequest(ctx context.Context, otp *OTP) error {
	return m.sendRequestErr
}

type testTransactor struct {
	singleErr error
	atomicErr error
}

func (t testTransactor) Single(ctx context.Context, work sqlx.TransactorWork) error {
	if err := work(ctx, nil); err != nil {
		return err
	}
	return t.singleErr
}

func (t testTransactor) Atomic(ctx context.Context, work sqlx.TransactorWork) error {
	if err := work(ctx, nil); err != nil {
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
				OTPStore:    test.otpStore,
				OTPMailer:   test.otpMailer,
				OTPDuration: 15 * time.Minute,
				Transactor:  test.transactor,
				Logger:      slog.New(slog.NewJSONHandler(t.Output(), nil)),
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
