package domain

import (
	"github.com/carafie/identity/platform/jwt"
)

type (
	AccessToken  = jwt.Token
	RefreshToken = jwt.Token
)
