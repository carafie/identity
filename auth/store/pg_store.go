package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/internal/database"
	"github.com/carafie/identity/internal/mail"
	"github.com/carafie/identity/internal/uuid"
)

type PgFactory struct{}

var _ Factory = PgFactory{}

func NewPgFactory() PgFactory {
	return PgFactory{}
}

func (f PgFactory) New(executor database.Executor) Store {
	if executor == nil {
		panic("store.PgFactory.New: database.Executor cannot be nil")
	}
	return &pg{executor: executor}
}

type pg struct {
	executor database.Executor
}

var _ Store = &pg{}

func (p *pg) CreateOTP(ctx context.Context, otp *domain.OTP) error {
	const query = `
		INSERT INTO otps(id, email, code, attempts, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := p.executor.ExecContext(ctx, query,
		otp.ID, otp.Email, otp.Code, otp.Attempts, otp.CreatedAt, otp.ExpiresAt,
	)
	return err
}

func (p *pg) ConsumeOTP(ctx context.Context, otpID uuid.UUID) (*domain.OTP, error) {
	const query = `
		UPDATE otps
	    SET attempts = attempts + 1
	    WHERE id = $1
	    RETURNING email, code, attempts, created_at, expires_at
	`
	row := otpRow{id: otpID}
	if err := p.executor.QueryRowContext(ctx, query, otpID).Scan(
		&row.email, &row.code, &row.attempts, &row.createdAt, &row.expiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, database.ErrNotFound
		}
		return nil, err
	}
	return row.Parse()
}

func (p *pg) DeleteOTP(ctx context.Context, otpID uuid.UUID) error {
	const query = `
		DELETE FROM otps
		WHERE id = $1
	`
	result, err := p.executor.ExecContext(ctx, query, otpID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return database.ErrNotFound
	}
	return nil
}

func (p *pg) GetUserByEmailOrCreate(ctx context.Context, user *domain.User) (*domain.User, error) {
	const query = `
		WITH inserted AS (
		    INSERT INTO users(id, email, email_normalized)
		    VALUES ($1, $2, $3)
		    ON CONFLICT(email_normalized) DO NOTHING
		    RETURNING id, email
		)
		SELECT id, email FROM inserted
		UNION ALL
		SELECT id, email FROM users WHERE email_normalized = $3
		LIMIT 1
	`
	var row userRow
	if err := p.executor.QueryRowContext(ctx, query, user.ID, user.Email, user.Email.Normalize()).Scan(
		&row.id, &row.email,
	); err != nil {
		return nil, err
	}
	return row.Parse()
}

func (p *pg) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	const query = `
		DELETE FROM users
		WHERE id = $1
	`
	result, err := p.executor.ExecContext(ctx, query, userID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return database.ErrNotFound
	}
	return nil
}

func (p *pg) CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	const query = `
		INSERT INTO refresh_tokens(id, user_id, email, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := p.executor.ExecContext(ctx, query,
		token.ID, token.UserID, token.Email, token.CreatedAt, token.ExpiresAt,
	)
	return err
}

func (p *pg) GetRefreshToken(ctx context.Context, userID, refreshTokenID uuid.UUID) (
	*domain.RefreshToken, error,
) {
	const query = `
		SELECT email, created_at, expires_at
		FROM refresh_tokens
		WHERE user_id = $1 AND id = $2
	`
	row := refreshTokenRow{id: refreshTokenID, userID: userID}
	if err := p.executor.QueryRowContext(ctx, query, userID, refreshTokenID).Scan(
		&row.email, &row.createdAt, &row.expiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, database.ErrNotFound
		}
		return nil, err
	}
	return row.Parse()
}

func (p *pg) ListRefreshTokens(ctx context.Context, userID uuid.UUID) ([]*domain.RefreshToken, error) {
	const query = `
		SELECT id, email, created_at, expires_at
		FROM refresh_tokens
		WHERE user_id = $1
	`
	rows, err := p.executor.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := make([]*domain.RefreshToken, 0)

	row := refreshTokenRow{userID: userID}
	for rows.Next() {
		if err := rows.Scan(&row.id, &row.email, &row.createdAt, &row.expiresAt); err != nil {
			return nil, err
		}
		token, err := row.Parse()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tokens, nil
}

func (p *pg) DeleteRefreshToken(ctx context.Context, userID, refreshTokenID uuid.UUID) error {
	const query = `
		DELETE FROM refresh_tokens
		WHERE user_id = $1 AND id = $2
	`
	result, err := p.executor.ExecContext(ctx, query, userID, refreshTokenID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return database.ErrNotFound
	}
	return nil
}

type otpRow struct {
	id        uuid.UUID
	email     string
	code      string
	attempts  int
	createdAt time.Time
	expiresAt time.Time
}

func (r otpRow) Parse() (*domain.OTP, error) {
	email, err := mail.Parse(r.email)
	if err != nil {
		return nil, err
	}
	code, err := domain.ParseCode(r.code)
	if err != nil {
		return nil, err
	}
	return domain.LoadOTP(r.id, email, code, r.attempts, r.createdAt, r.expiresAt), nil
}

type userRow struct {
	id    uuid.UUID
	email string
}

func (r userRow) Parse() (*domain.User, error) {
	email, err := mail.Parse(r.email)
	if err != nil {
		return nil, err
	}
	return domain.LoadUser(r.id, email), nil
}

type refreshTokenRow struct {
	id        uuid.UUID
	userID    uuid.UUID
	email     string
	createdAt time.Time
	expiresAt time.Time
}

func (r refreshTokenRow) Parse() (*domain.RefreshToken, error) {
	email, err := mail.Parse(r.email)
	if err != nil {
		return nil, err
	}
	return domain.LoadRefreshToken(r.id, r.userID, email, r.createdAt, r.expiresAt), nil
}
