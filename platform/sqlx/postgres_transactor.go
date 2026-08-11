package sqlx

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/carafie/identity/platform/requestid"
	"github.com/carafie/identity/platform/slogx"
)

type PostgresTransactor struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPostgresTransactor(db *sql.DB, logger *slog.Logger) *PostgresTransactor {
	if db == nil {
		panic("db cannot be nil")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &PostgresTransactor{
		db:     db,
		logger: logger,
	}
}

func (t *PostgresTransactor) Single(ctx context.Context, work TransactorSingleWork) error {
	return work(ctx, t.db)
}

func (t *PostgresTransactor) Atomic(ctx context.Context, work TransactorAtomicWork) error {
	l := t.logger.With(slogx.RequestID(requestid.FromContext(ctx)))

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		l.ErrorContext(ctx, "begin transaction", slogx.Error(err))
		return err
	}
	defer tx.Rollback()

	tcl, err := work(ctx, tx)
	if tcl == Commit {
		if err := tx.Commit(); err != nil {
			l.ErrorContext(ctx, "commit transaction", slogx.Error(err))
			return err
		}
	}
	return err
}
