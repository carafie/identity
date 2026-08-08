package domain

import (
	"errors"

	"github.com/carafie/identity/platform/jwt"
)

var (
	ErrTokenInvalid = errors.New("token is invalid")
	ErrTokenExpired = errors.New("token is expired")
	ErrTokenRevoked = errors.New("token is revoked")
)

type (
	AccessToken  = jwt.Token
	RefreshToken = jwt.Token
)
