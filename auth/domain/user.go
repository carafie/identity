package domain

import (
	"errors"

	"github.com/carafie/identity/internal/mail"
	"github.com/carafie/identity/internal/uuid"
)

var ErrUserNotFound = errors.New("user not found")

type User struct {
	ID    uuid.UUID
	Email mail.Email
}

func NewUser(email mail.Email) *User {
	return &User{
		ID:    uuid.New(),
		Email: email,
	}
}

func LoadUser(id uuid.UUID, email mail.Email) *User {
	return &User{
		ID:    id,
		Email: email,
	}
}
