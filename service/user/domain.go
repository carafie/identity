package user

import (
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/uuid"
)

type User struct {
	ID    uuid.UUID
	Email mail.Email
}

func New(email mail.Email) *User {
	return &User{
		ID:    uuid.New(),
		Email: email,
	}
}
