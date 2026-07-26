package email

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		shouldErr bool
	}{
		{"too long", strings.Repeat("a", maxBytes+1), true},
		{"invalid", "@", true},
		{"with display name", "John <john@example.org>", true},
		{"local part too long", strings.Repeat("a", maxLocalBytes+1) + "@example.org", true},
		{"success", "john@example.org", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.email)
			if (err != nil) != test.shouldErr {
				t.Errorf(
					"Parse(%q), shouldErr = %v, gotErr = %v",
					test.email, test.shouldErr, err,
				)
			}
		})
	}
}
