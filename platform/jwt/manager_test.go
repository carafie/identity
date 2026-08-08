package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/uuid"
	"github.com/google/go-cmp/cmp"
)

func TestManager_SignAndParse(t *testing.T) {
	newManager := func(t *testing.T) *Manager {
		t.Helper()
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}
		return NewManager(publicKey, privateKey)
	}

	email, err := mail.Parse("jwt@test")
	if err != nil {
		t.Fatalf("failed to parse email: %v", err)
	}

	t.Run("keys mismatch", func(t *testing.T) {
		manager1 := newManager(t)
		manager2 := newManager(t)

		fields := NewTokenFields(uuid.New(), email, KindRefresh, time.Hour)
		token, err := manager1.Sign(fields)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		_, err = manager2.Parse(token.JWS)
		if err == nil {
			t.Error("parsing token with different key pair should fail")
		}
	})

	t.Run("token expired", func(t *testing.T) {
		manager := newManager(t)

		fields := NewTokenFields(uuid.New(), email, KindRefresh, -time.Hour)
		token, err := manager.Sign(fields)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		_, err = manager.Parse(token.JWS)
		if err == nil {
			t.Error("parsing expired token should fail")
		}
	})

	t.Run("success", func(t *testing.T) {
		manager := newManager(t)

		fields := NewTokenFields(uuid.New(), email, KindRefresh, time.Hour)
		token, err := manager.Sign(fields)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		gotToken, err := manager.Parse(token.JWS)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}
		if diff := cmp.Diff(fields, gotToken.Fields); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})
}
