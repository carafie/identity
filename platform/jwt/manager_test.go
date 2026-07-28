package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/carafie/identity/platform/email"
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

	em, err := email.Parse("jwt@test")
	if err != nil {
		t.Fatalf("failed to parse email: %v", err)
	}

	t.Run("keys mismatch", func(t *testing.T) {
		manager1 := newManager(t)
		manager2 := newManager(t)

		fields := NewTokenFields(uuid.New(), em, KindRefresh, time.Hour)
		signed, err := manager1.Sign(fields)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		_, err = manager2.Parse(signed)
		if err == nil {
			t.Error("parsing token with different key pair should fail")
		}
	})

	t.Run("token expired", func(t *testing.T) {
		manager := newManager(t)

		fields := NewTokenFields(uuid.New(), em, KindRefresh, -time.Hour)
		signed, err := manager.Sign(fields)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		_, err = manager.Parse(signed)
		if err == nil {
			t.Error("parsing expired token should fail")
		}
	})

	t.Run("success", func(t *testing.T) {
		manager := newManager(t)

		fields := NewTokenFields(uuid.New(), em, KindRefresh, time.Hour)
		signed, err := manager.Sign(fields)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		gotFields, err := manager.Parse(signed)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}
		if diff := cmp.Diff(fields, gotFields); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})
}
