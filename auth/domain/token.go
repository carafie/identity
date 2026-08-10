package domain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/carafie/identity/platform/clock"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/uuid"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrTokenInvalid  = errors.New("token is invalid")
	ErrTokenExpired  = errors.New("token is expired")
	ErrTokenNotFound = errors.New("token not found")

	ErrTokenKindInvalid = errors.New("token kind is invalid")
)

type (
	AccessToken  Token
	RefreshToken Token

	// JWS is the JSON Web Signature, commonly referred to as the signed string.
	JWS = string
)

type Token struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Email     mail.Email
	Kind      Kind
	CreatedAt time.Time
	ExpiresAt time.Time

	// JWS is populated after successful call to [TokenManager.SignAccess] or [TokenManager.SignRefresh].
	JWS JWS
}

func NewAccessToken(userID uuid.UUID, email mail.Email, duration time.Duration) *AccessToken {
	return (*AccessToken)(newToken(userID, email, KindAccess, duration))
}

func NewRefreshToken(userID uuid.UUID, email mail.Email, duration time.Duration) *RefreshToken {
	return (*RefreshToken)(newToken(userID, email, KindRefresh, duration))
}

func newToken(userID uuid.UUID, email mail.Email, kind Kind, duration time.Duration) *Token {
	now := clock.Normalize(time.Now())
	return &Token{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     email,
		Kind:      kind,
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
	}
}

func loadToken(id, userID uuid.UUID, email mail.Email, kind Kind, createdAt, expiresAt time.Time) *Token {
	return &Token{
		ID:        id,
		UserID:    userID,
		Email:     email,
		Kind:      kind,
		CreatedAt: clock.Normalize(createdAt),
		ExpiresAt: clock.Normalize(expiresAt),
	}
}

type Kind int

const (
	KindAccess Kind = 1 + iota
	KindRefresh
)

func ParseKind(kind int) (Kind, error) {
	switch kind {
	case int(KindAccess):
		return KindAccess, nil
	case int(KindRefresh):
		return KindRefresh, nil
	default:
		return 0, ErrTokenKindInvalid
	}
}

type claims struct {
	Email string `json:"email"`
	Kind  int    `json:"kind"`
	jwt.RegisteredClaims
}

func claimsFromToken(token *Token) *claims {
	return &claims{
		Email: string(token.Email),
		Kind:  int(token.Kind),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        token.ID.String(),
			Subject:   token.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(token.CreatedAt),
			ExpiresAt: jwt.NewNumericDate(token.ExpiresAt),
		},
	}
}

type TokenManager struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	parser     *jwt.Parser
}

func NewTokenManager(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) *TokenManager {
	if publicKey == nil {
		panic("public key cannot be nil")
	}
	if privateKey == nil {
		panic("private key cannot be nil")
	}
	return &TokenManager{
		publicKey:  publicKey,
		privateKey: privateKey,
		parser: jwt.NewParser(
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		),
	}
}

func (m *TokenManager) SignAccess(token *AccessToken) error {
	if token.Kind != KindAccess {
		return ErrTokenKindInvalid
	}
	return m.sign((*Token)(token))
}

func (m *TokenManager) SignRefresh(token *RefreshToken) error {
	if token.Kind != KindRefresh {
		return ErrTokenKindInvalid
	}
	return m.sign((*Token)(token))
}

func (m *TokenManager) sign(token *Token) error {
	claims := claimsFromToken(token)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedString, err := jwtToken.SignedString(m.privateKey)
	if err != nil {
		return err
	}
	token.JWS = signedString
	return nil
}

func (m *TokenManager) ParseAccess(jws JWS) (*AccessToken, error) {
	token, err := m.parse(jws)
	if err != nil {
		return nil, err
	}
	if token.Kind != KindAccess {
		return nil, ErrTokenKindInvalid
	}
	return (*AccessToken)(token), nil
}

func (m *TokenManager) ParseRefresh(jws JWS) (*RefreshToken, error) {
	token, err := m.parse(jws)
	if err != nil {
		return nil, err
	}
	if token.Kind != KindRefresh {
		return nil, ErrTokenKindInvalid
	}
	return (*RefreshToken)(token), nil
}

func (m *TokenManager) parse(jws JWS) (*Token, error) {
	jwtToken, err := m.parser.ParseWithClaims(
		jws,
		&claims{},
		func(t *jwt.Token) (any, error) { return m.publicKey, nil },
	)
	if err != nil {
		return nil, err
	}

	claims, ok := jwtToken.Claims.(*claims)
	if !ok {
		// This should never happen.
		return nil, fmt.Errorf("unexpected claims type: %T", jwtToken.Claims)
	}

	id, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, err
	}
	email, err := mail.Parse(claims.Email)
	if err != nil {
		return nil, err
	}
	kind, err := ParseKind(claims.Kind)
	if err != nil {
		return nil, err
	}
	token := loadToken(id, userID, email, kind, claims.IssuedAt.Time, claims.ExpiresAt.Time)
	token.JWS = jws
	return token, nil
}
