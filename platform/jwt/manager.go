package jwt

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/carafie/identity/platform/email"
	"github.com/carafie/identity/platform/uuid"
	"github.com/golang-jwt/jwt/v5"
)

var (
	errTokenNil             = errors.New("token is nil")
	errUnexpectedClaimsType = errors.New("unexpected claims type")
)

type SignedToken = string

type Manager struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	parser     *jwt.Parser
}

func NewManager(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) *Manager {
	if publicKey == nil {
		panic("public key cannot be nil")
	}
	if privateKey == nil {
		panic("private key cannot be nil")
	}
	return &Manager{
		publicKey:  publicKey,
		privateKey: privateKey,
		parser: jwt.NewParser(
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		),
	}
}

func (m *Manager) New(token *Token) (SignedToken, error) {
	if token == nil {
		return "", errTokenNil
	}
	claims := NewClaims(token)
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(m.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	return signed, nil
}

func (m *Manager) Parse(signedToken SignedToken) (*Token, error) {
	parsed, err := m.parser.ParseWithClaims(
		signedToken,
		&Claims{},
		func(t *jwt.Token) (any, error) { return m.publicKey, nil },
	)
	if err != nil {
		return nil, err
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok {
		// This should never happen.
		return nil, errUnexpectedClaimsType
	}

	id, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, err
	}
	em, err := email.Parse(claims.Email)
	if err != nil {
		return nil, err
	}
	kind, err := NewKind(claims.Kind)
	if err != nil {
		return nil, err
	}
	return NewToken(id, userID, em, kind, claims.IssuedAt.Time, claims.ExpiresAt.Time), nil
}
