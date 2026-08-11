package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/auth/handler"
	"github.com/carafie/identity/auth/mailer"
	"github.com/carafie/identity/auth/service"
	"github.com/carafie/identity/auth/store"
	"github.com/carafie/identity/platform/slogx"
	"github.com/carafie/identity/platform/sqlx"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	config, err := parseConfig()
	if err != nil {
		fmt.Printf("failed to parse config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{Level: config.logLevel},
	))
	slog.SetDefault(logger)
	slog.SetLogLoggerLevel(config.logLevel)

	tokenManager := domain.NewTokenManager(config.jwtPublicKey, config.jwtPrivateKey)

	postgresDB, err := sql.Open("pgx", config.databasePostgresDSN)
	if err != nil {
		fmt.Printf("failed to open database: %v\n", err)
		os.Exit(2)
	}
	postgresTransactor := sqlx.NewPostgresTransactor(postgresDB, logger)
	postgresStoreProvider := store.PostgresProvider{}

	mailerParams := mailer.Params{
		FromAddress:           config.mailerFromAddress,
		SendOTPRequestSubject: config.mailerOTPRequestSubject,
		SendOTPRequestContent: config.mailerOTPRequestContent,
	}
	var mailerImpl mailer.Mailer
	switch config.mailer {
	case "resend":
		mailerImpl = mailer.NewResend(config.mailerResendAPIKey, config.mailerTimeout, mailerParams)
	case "log":
		mailerImpl = mailer.NewLog(logger, mailerParams)
	default:
		fmt.Printf("unexpected mailer: %q\n", config.mailer)
		os.Exit(3)
	}

	authService := service.New(&service.Params{
		StoreProvider:        &postgresStoreProvider,
		Mailer:               mailerImpl,
		OTPDuration:          config.otpDuration,
		OTPMaxAttempts:       config.otpMaxAttempts,
		TokenManager:         tokenManager,
		TokenAccessDuration:  config.jwtAccessDuration,
		TokenRefreshDuration: config.jwtRefreshDuration,
		Transactor:           postgresTransactor,
		Logger:               logger,
	})

	mux := http.NewServeMux()
	authHandler := handler.New(authService)
	authHandler.RegisterRequestOTP(mux)
	authHandler.RegisterConfirmOTP(mux)
	authHandler.RegisterRefreshAccessToken(mux)
	authHandler.RegisterListRefreshTokens(mux)
	authHandler.RegisterDeleteRefreshToken(mux)
	authHandler.RegisterDeleteUser(mux)

	server := &http.Server{
		Addr:         config.httpAddress,
		Handler:      handler.WithRequestID(mux),
		ReadTimeout:  config.httpReadTimeout,
		WriteTimeout: config.httpWriteTimeout,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), config.logLevel),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Error("http server listen and serve", slogx.Error(err))
				os.Exit(4)
			}
		}
	}()

	<-ctx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), config.httpReadTimeout+config.httpWriteTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("http server shutdown", slogx.Error(err))
		os.Exit(5)
	}
	logger.Info("http server graceful shutdown")
}

type config struct {
	httpAddress      string
	httpReadTimeout  time.Duration
	httpWriteTimeout time.Duration

	otpDuration    time.Duration
	otpMaxAttempts int

	jwtPublicKey       ed25519.PublicKey
	jwtPrivateKey      ed25519.PrivateKey
	jwtAccessDuration  time.Duration
	jwtRefreshDuration time.Duration

	databasePostgresDSN string

	mailer                  string
	mailerResendAPIKey      string
	mailerTimeout           time.Duration
	mailerFromAddress       string
	mailerOTPRequestSubject string
	mailerOTPRequestContent string

	logLevel slog.Level
}

func parseConfig() (*config, error) {
	httpAddress := os.Getenv("HTTP_ADDRESS")
	httpReadTimeoutSeconds, err := strconv.Atoi(os.Getenv("HTTP_READ_TIMEOUT_SECONDS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP_READ_TIMEOUT_SECONDS: %w", err)
	}
	httpWriteTimeoutSeconds, err := strconv.Atoi(os.Getenv("HTTP_WRITE_TIMEOUT_SECONDS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP_WRITE_TIMEOUT_SECONDS: %w", err)
	}

	otpDurationSeconds, err := strconv.Atoi(os.Getenv("OTP_DURATION_SECONDS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse OTP_DURATION_SECONDS: %w", err)
	}
	otpMaxAttempts, err := strconv.Atoi(os.Getenv("OTP_MAX_ATTEMPTS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse OTP_MAX_ATTEMPTS: %w", err)
	}

	jwtPublicKeyFileBytes, err := os.ReadFile(os.Getenv("JWT_PUBLIC_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT_PUBLIC_KEY_FILE: %w", err)
	}
	jwtPublicKeyBlock, _ := pem.Decode(jwtPublicKeyFileBytes)
	if jwtPublicKeyBlock == nil {
		return nil, fmt.Errorf("failed to parse JWT_PUBLIC_KEY_FILE: failed to decode PEM block")
	}
	jwtPublicKeyAny, err := x509.ParsePKIXPublicKey(jwtPublicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT_PUBLIC_KEY_FILE: %w", err)
	}
	jwtPublicKey, ok := jwtPublicKeyAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse JWT_PUBLIC_KEY_FILE: key is not Ed25519 public key")
	}

	jwtPrivateKeyFileBytes, err := os.ReadFile(os.Getenv("JWT_PRIVATE_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT_PRIVATE_KEY_FILE: %w", err)
	}
	jwtPrivateKeyBlock, _ := pem.Decode(jwtPrivateKeyFileBytes)
	if jwtPrivateKeyBlock == nil {
		return nil, fmt.Errorf("failed to parse JWT_PRIVATE_KEY_FILE: failed to decode PEM block")
	}
	jwtPrivateKeyAny, err := x509.ParsePKCS8PrivateKey(jwtPrivateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT_PRIVATE_KEY_FILE: %w", err)
	}
	jwtPrivateKey, ok := jwtPrivateKeyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse JWT_PRIVATE_KEY_FILE: key is not Ed25519 private key")
	}

	jwtAccessDurationSeconds, err := strconv.Atoi(os.Getenv("JWT_ACCESS_DURATION_SECONDS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT_ACCESS_DURATION_SECONDS: %w", err)
	}
	jwtRefreshDurationSeconds, err := strconv.Atoi(os.Getenv("JWT_REFRESH_DURATION_SECONDS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT_REFRESH_DURATION_SECONDS: %w", err)
	}

	databasePostgresDSN := os.Getenv("DATABASE_POSTGRES_DSN")

	mailer := os.Getenv("MAILER")
	mailerResendAPIKey := os.Getenv("MAILER_RESEND_API_KEY")
	mailerTimeoutSeconds, err := strconv.Atoi(os.Getenv("MAILER_TIMEOUT_SECONDS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAILER_TIMEOUT_SECONDS: %w", err)
	}
	mailerFromAddress := os.Getenv("MAILER_FROM_ADDRESS")
	mailerOTPRequestSubject := os.Getenv("MAILER_OTP_REQUEST_SUBJECT")
	mailerOTPRequestContent := os.Getenv("MAILER_OTP_REQUEST_CONTENT")

	return &config{
		httpAddress:      httpAddress,
		httpReadTimeout:  time.Duration(httpReadTimeoutSeconds) * time.Second,
		httpWriteTimeout: time.Duration(httpWriteTimeoutSeconds) * time.Second,

		otpDuration:    time.Duration(otpDurationSeconds) * time.Second,
		otpMaxAttempts: otpMaxAttempts,

		jwtPublicKey:       jwtPublicKey,
		jwtPrivateKey:      jwtPrivateKey,
		jwtAccessDuration:  time.Duration(jwtAccessDurationSeconds) * time.Second,
		jwtRefreshDuration: time.Duration(jwtRefreshDurationSeconds) * time.Second,

		databasePostgresDSN: databasePostgresDSN,

		mailer:                  mailer,
		mailerResendAPIKey:      mailerResendAPIKey,
		mailerTimeout:           time.Duration(mailerTimeoutSeconds) * time.Second,
		mailerFromAddress:       mailerFromAddress,
		mailerOTPRequestSubject: mailerOTPRequestSubject,
		mailerOTPRequestContent: mailerOTPRequestContent,

		logLevel: slog.LevelInfo,
	}, nil
}
