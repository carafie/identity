package domain

import (
	"errors"

	"github.com/carafie/identity/platform/jwt"
)

var (
	ErrTokenInvalid  = errors.New("token is invalid")
	ErrTokenExpired  = errors.New("token is expired")
	ErrTokenNotFound = errors.New("token not found")
)

type (
	AccessToken  = jwt.Token
	RefreshToken = jwt.Token

	AccessTokenFields  = jwt.TokenFields
	RefreshTokenFields = jwt.TokenFields
)
