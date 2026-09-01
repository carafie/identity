package domain

import (
	"errors"
	"uuid"

	"github.com/carafie/identity/internal/mail"
)

var ErrUserNotFound = errors.New("user not found")

type User struct {
	ID    uuid.UUID
	Email mail.Email
}

func NewUser(email mail.Email) *User {
	return &User{
		ID:    uuid.NewV7(),
		Email: email,
	}
}

func LoadUser(id uuid.UUID, email mail.Email) *User {
	return &User{
		ID:    id,
		Email: email,
	}
}
