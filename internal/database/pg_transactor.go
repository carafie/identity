package database

import (
	"context"
	"fmt"
)

type PgTransactor struct {
	db *DB
}

func NewPgTransactor(db *DB) *PgTransactor {
	if db == nil {
		panic("database.NewPgTransactor: *DB cannot be nil")
	}
	return &PgTransactor{db: db}
}

func (t *PgTransactor) Single(ctx context.Context, work Work) error {
	if work == nil {
		return ErrWorkNil
	}

	if err := work(ctx, t.db.Pool); err != nil {
		return err
	}

	return nil
}

func (t *PgTransactor) Atomic(ctx context.Context, work Work) error {
	if work == nil {
		return ErrWorkNil
	}

	tx, err := t.db.Pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := work(ctx, tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
