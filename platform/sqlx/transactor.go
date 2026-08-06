package sqlx

import (
	"context"
)

type Transactor interface {
	Single(ctx context.Context, work TransactorWork) error
	Atomic(ctx context.Context, work TransactorWork) error
}

type TransactorWork func(ctx context.Context, executor Executor) error
