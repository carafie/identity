package domain

import (
	"log/slog"

	"github.com/carafie/identity/internal/uuid"
)

const (
	logKeyUserID         = "user_id"
	logKeyOTPID          = "otp_id"
	logKeyRefreshTokenID = "refresh_token_id"
)

func UserID(id uuid.UUID) slog.Attr {
	return slog.String(logKeyUserID, id.String())
}

func OTPID(id uuid.UUID) slog.Attr {
	return slog.String(logKeyOTPID, id.String())
}

func RefreshTokenID(id uuid.UUID) slog.Attr {
	return slog.String(logKeyRefreshTokenID, id.String())
}
