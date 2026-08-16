package uuid

import (
	"errors"

	"github.com/google/uuid"
)

var ErrInvalid = errors.New("uuid is invalid")

type UUID = uuid.UUID

func New() UUID {
	return uuid.Must(uuid.NewV7())
}

func Parse(text string) (UUID, error) {
	id, err := uuid.Parse(text)
	if err != nil {
		return UUID{}, ErrInvalid
	}
	return id, nil
}
