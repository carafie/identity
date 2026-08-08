package requestid

import (
	"context"

	"github.com/carafie/identity/platform/uuid"
)

type ctxKey int

var key ctxKey

func FromContext(ctx context.Context) uuid.UUID {
	if id, ok := ctx.Value(key).(uuid.UUID); ok {
		return id
	}
	return uuid.UUID{}
}
