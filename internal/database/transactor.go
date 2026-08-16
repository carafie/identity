package database

import (
	"context"
	"errors"
)

var ErrWorkNil = errors.New("work function cannot be nil")

// Transactor abstracts database transactions.
type Transactor interface {
	// Single runs work function in an implicit transaction.
	// It does not wrap any error returned from that work function.
	Single(ctx context.Context, work Work) error

	// Atomic runs work function in an explicit transaction.
	// It commits on work success and rollbacks on error.
	//
	// It does not wrap any error returned from that work function,
	// but might return other errors such as failure to begin or commit a transaction.
	Atomic(ctx context.Context, work Work) error
}

type Work func(ctx context.Context, executor Executor) error
