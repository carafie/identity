package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/internal/database"
	"github.com/carafie/identity/internal/database/databasetest"
	"github.com/carafie/identity/internal/mail"
	"github.com/carafie/identity/internal/uuid"
	"github.com/google/go-cmp/cmp"
)

var (
	testPgDB      *database.DB
	testPgFactory PgFactory
	testEmail     mail.Email
)

func newTestPgStore(t *testing.T) *pg {
	t.Helper()

	tx, err := testPgDB.Pool.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}
	t.Cleanup(func() { tx.Rollback() })

	return testPgFactory.New(tx).(*pg)
}

func insertTestOTP(t *testing.T, store *pg) *domain.OTP {
	t.Helper()

	otp := domain.NewOTP(testEmail, time.Hour)
	query := `
		INSERT INTO otps(id, email, code, attempts, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := store.executor.ExecContext(t.Context(), query,
		otp.ID, otp.Email, otp.Code, otp.Attempts, otp.CreatedAt, otp.ExpiresAt,
	)
	if err != nil {
		t.Fatalf("failed to insert otp row: %v", err)
	}
	return otp
}

func insertTestUser(t *testing.T, store *pg) *domain.User {
	t.Helper()

	user := domain.NewUser(testEmail)
	query := `
			INSERT INTO users(id, email, email_normalized)
			VALUES ($1, $2, $3)
		`
	_, err := store.executor.ExecContext(t.Context(), query,
		user.ID, user.Email, user.Email.Normalize(),
	)
	if err != nil {
		t.Fatalf("failed to insert user row: %v", err)
	}
	return user
}

func insertTestRefreshToken(t *testing.T, store *pg, userID uuid.UUID) *domain.RefreshToken {
	t.Helper()

	refreshToken := domain.NewRefreshToken(userID, testEmail, time.Hour)
	query := `
		INSERT INTO refresh_tokens(id, user_id, email, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := store.executor.ExecContext(t.Context(), query,
		refreshToken.ID, refreshToken.UserID, refreshToken.Email, refreshToken.CreatedAt, refreshToken.ExpiresAt,
	)
	if err != nil {
		t.Fatalf("failed to insert refresh token row: %v", err)
	}
	return refreshToken
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	db, close, err := databasetest.Open(ctx)
	cancel()
	if err != nil {
		panic(fmt.Errorf("store.TestMain: failed to open test database: %w", err))
	}

	testPgDB = db
	testPgFactory = NewPgFactory()
	testEmail, err = mail.Parse("store@test")
	if err != nil {
		panic(fmt.Errorf("store.TestMain: failed to parse email: %w", err))
	}

	code := m.Run()
	close()
	os.Exit(code)
}

func TestPg_CreateOTP(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)

		otp := domain.NewOTP(testEmail, time.Hour)
		if err := store.CreateOTP(t.Context(), otp); err != nil {
			t.Fatalf("CreateOTP(), gotErr=%v, wantErr=%v", err, nil)
		}

		query := `
			SELECT email, code, attempts, created_at, expires_at
			FROM otps
			WHERE id = $1
		`
		row := otpRow{id: otp.ID}
		err := store.executor.QueryRowContext(t.Context(), query, otp.ID).Scan(
			&row.email, &row.code, &row.attempts, &row.createdAt, &row.expiresAt,
		)
		if err != nil {
			t.Fatalf("failed to scan inserted otp row: %v", err)
		}

		foundOTP, err := row.parse()
		if err != nil {
			t.Fatalf("failed to parse inserted otp row: %v", err)
		}
		if diff := cmp.Diff(foundOTP, otp); diff != "" {
			t.Errorf("CreateOTP() mismatch (-got +want):\n%s", diff)
		}
	})
}

func TestPg_ConsumeOTP(t *testing.T) {
	t.Parallel()

	t.Run("otp not found", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)

		_, err := store.ConsumeOTP(t.Context(), uuid.New())
		if !errors.Is(err, database.ErrNotFound) {
			t.Errorf("ConsumeOTP(), gotErr=%v, wantErr=%v", err, database.ErrNotFound)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)
		otp := insertTestOTP(t, store)

		consumedOTP, err := store.ConsumeOTP(t.Context(), otp.ID)
		if err != nil {
			t.Fatalf("ConsumeOTP(), gotErr=%v, wantErr=%v", err, nil)
		}
		otp.Attempts += 1
		if diff := cmp.Diff(consumedOTP, otp); diff != "" {
			t.Errorf("ConsumeOTP() mismatch (-got +want):\n%s", diff)
		}
	})
}

func TestPg_DeleteOTP(t *testing.T) {
	t.Parallel()

	t.Run("otp not found", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)

		if err := store.DeleteOTP(t.Context(), uuid.New()); !errors.Is(err, database.ErrNotFound) {
			t.Fatalf("DeleteOTP(), gotErr=%v, wantErr=%v", err, database.ErrNotFound)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)
		otp := insertTestOTP(t, store)

		if err := store.DeleteOTP(t.Context(), otp.ID); err != nil {
			t.Fatalf("DeleteOTP(), gotErr=%v, wantErr=%v", err, nil)
		}

		query := `
			SELECT email, code, attempts, created_at, expires_at
			FROM otps
			WHERE id = $1
		`
		row := otpRow{id: otp.ID}
		err := store.executor.QueryRowContext(t.Context(), query, otp.ID).Scan(
			&row.email, &row.code, &row.attempts, &row.createdAt, &row.expiresAt,
		)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("failed to verify deleted otp row: %v", err)
		}
	})
}

func TestPg_GetUserByEmailOrCreate(t *testing.T) {
	t.Parallel()

	t.Run("user not found", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)

		user := domain.NewUser(testEmail)
		returnedUser, err := store.GetUserByEmailOrCreate(t.Context(), user)
		if err != nil {
			t.Fatalf("GetUserByEmailOrCreate(), gotErr=%v, wantErr=%v", err, nil)
		}
		if diff := cmp.Diff(returnedUser, user); diff != "" {
			t.Fatalf("GetUserByEmailOrCreate() mismatch (-got +want):\n%s", diff)
		}

		query := `
			SELECT email
			FROM users
			WHERE id = $1
		`
		row := userRow{id: user.ID}
		err = store.executor.QueryRowContext(t.Context(), query, user.ID).Scan(
			&row.email,
		)
		if err != nil {
			t.Fatalf("failed to select inserted user row: %v", err)
		}

		foundUser, err := row.parse()
		if err != nil {
			t.Fatalf("failed to parse inserted user row: %v", err)
		}
		if diff := cmp.Diff(foundUser, user); diff != "" {
			t.Errorf("GetUserByEmailOrCreate() mismatch (-got +want):\n%s", diff)
		}
	})

	t.Run("user found", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)
		user := insertTestUser(t, store)

		returnedUser, err := store.GetUserByEmailOrCreate(t.Context(), user)
		if err != nil {
			t.Fatalf("GetUserByEmailOrCreate(), gotErr=%v, wantErr=%v", err, nil)
		}
		if diff := cmp.Diff(returnedUser, user); diff != "" {
			t.Errorf("GetUserByEmailOrCreate() mismatch (-got +want):\n%s", diff)
		}
	})
}

func TestPg_DeleteUser(t *testing.T) {
	t.Parallel()

	t.Run("user not found", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)

		err := store.DeleteUser(t.Context(), uuid.New())
		if !errors.Is(err, database.ErrNotFound) {
			t.Errorf("DeleteUser(), gotErr=%v, wantErr=%v", err, database.ErrNotFound)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)
		user := insertTestUser(t, store)

		if err := store.DeleteUser(t.Context(), user.ID); err != nil {
			t.Fatalf("DeleteUser(), gotErr=%v, wantErr=%v", err, nil)
		}

		query := `
			SELECT email
			FROM users
			WHERE id = $1
		`
		row := userRow{id: user.ID}
		err := store.executor.QueryRowContext(t.Context(), query, user.ID).Scan(
			&row.email,
		)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("failed to verify deleted user row: %v", err)
		}
	})
}

func TestPg_CreateRefreshToken(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)
		user := insertTestUser(t, store)

		refreshToken := domain.NewRefreshToken(user.ID, testEmail, time.Hour)
		if err := store.CreateRefreshToken(t.Context(), refreshToken); err != nil {
			t.Fatalf("CreateRefreshToken(), gotErr=%v, wantErr=%v", err, nil)
		}

		query := `
			SELECT user_id, email, created_at, expires_at
			FROM refresh_tokens
			WHERE id = $1
		`
		row := refreshTokenRow{id: refreshToken.ID}
		err := store.executor.QueryRowContext(t.Context(), query, refreshToken.ID).Scan(
			&row.userID, &row.email, &row.createdAt, &row.expiresAt,
		)
		if err != nil {
			t.Fatalf("failed to select inserted refresh token row: %v", err)
		}

		foundRefreshToken, err := row.parse()
		if err != nil {
			t.Fatalf("failed to parse inserted refresh token row: %v", err)
		}
		if diff := cmp.Diff(foundRefreshToken, refreshToken); diff != "" {
			t.Errorf("CreateRefreshToken() mismatch (-got +want):\n%s", diff)
		}
	})
}

func TestPg_GetRefreshToken(t *testing.T) {
	t.Parallel()

	t.Run("refresh token not found", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)

		_, err := store.GetRefreshToken(t.Context(), uuid.New(), uuid.New())
		if !errors.Is(err, database.ErrNotFound) {
			t.Errorf("GetRefreshToken(), gotErr=%v, wantErr=%v", err, database.ErrNotFound)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)
		user := insertTestUser(t, store)
		refreshToken := insertTestRefreshToken(t, store, user.ID)

		foundRefreshToken, err := store.GetRefreshToken(t.Context(), refreshToken.UserID, refreshToken.ID)
		if err != nil {
			t.Fatalf("GetRefreshToken(), gotErr=%v, wantErr=%v", err, nil)
		}
		if diff := cmp.Diff(foundRefreshToken, refreshToken); diff != "" {
			t.Errorf("GetRefreshToken() mismatch (-got +want):\n%s", diff)
		}
	})
}

func TestPg_ListRefreshTokens(t *testing.T) {
	t.Parallel()

	t.Run("refresh tokens not found", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)

		refreshTokens, err := store.ListRefreshTokens(t.Context(), uuid.New())
		if err != nil {
			t.Fatalf("ListRefreshTokens(), gotErr=%v, wantErr=%v", err, nil)
		}
		if diff := cmp.Diff(refreshTokens, []*domain.RefreshToken{}); diff != "" {
			t.Errorf("GetRefreshToken() mismatch (-got +want):\n%s", diff)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)
		user := insertTestUser(t, store)
		refreshToken := insertTestRefreshToken(t, store, user.ID)

		foundRefreshTokens, err := store.ListRefreshTokens(t.Context(), refreshToken.UserID)
		if err != nil {
			t.Fatalf("ListRefreshTokens(), gotErr=%v, wantErr=%v", err, nil)
		}
		if diff := cmp.Diff(foundRefreshTokens, []*domain.RefreshToken{refreshToken}); diff != "" {
			t.Errorf("ListRefreshTokens() mismatch (-got +want):\n%s", diff)
		}
	})
}

func TestPg_DeleteRefreshToken(t *testing.T) {
	t.Parallel()

	t.Run("refresh token not found", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)

		err := store.DeleteRefreshToken(t.Context(), uuid.New(), uuid.New())
		if !errors.Is(err, database.ErrNotFound) {
			t.Errorf("DeleteRefreshToken(), gotErr=%v, wantErr=%v", err, database.ErrNotFound)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestPgStore(t)
		user := insertTestUser(t, store)
		refreshToken := insertTestRefreshToken(t, store, user.ID)

		if err := store.DeleteRefreshToken(t.Context(), refreshToken.UserID, refreshToken.ID); err != nil {
			t.Errorf("DeleteRefreshToken(), gotErr=%v, wantErr=%v", err, nil)
		}
	})
}
