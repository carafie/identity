package sqlx

import (
	"context"
)

type Transactor interface {
	Single(ctx context.Context, work TransactorSingleWork) error
	Atomic(ctx context.Context, work TransactorAtomicWork) error
}

type TransactorSingleWork func(ctx context.Context, executor Executor) error

type TransactorAtomicWork func(ctx context.Context, executor Executor) (TCL, error)

type TCL int

const (
	Commit TCL = iota + 1
	Rollback
)
