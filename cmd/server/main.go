package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	authDomain "github.com/carafie/identity/auth/domain"
	authHandler "github.com/carafie/identity/auth/handler"
	authMailer "github.com/carafie/identity/auth/mailer"
	authService "github.com/carafie/identity/auth/service"
	authStore "github.com/carafie/identity/auth/store"
	"github.com/carafie/identity/internal/database"
	"github.com/carafie/identity/internal/logging"
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

	tokenManager := authDomain.NewTokenManager(config.jwtPublicKey, config.jwtPrivateKey)

	db, err := database.Open(database.Config{
		DataSourceName:  config.databaseDataSourceName,
		MaxIdleConns:    config.databaseMaxIdleConns,
		MaxOpenConns:    config.databaseMaxOpenConns,
		ConnMaxIdleTime: config.databaseConnMaxIdleTime,
		ConnMaxLifetime: config.databaseConnMaxLifetime,
	})
	if err != nil {
		fmt.Printf("failed to open database: %v\n", err)
		os.Exit(2)
	}
	defer db.Close()
	transactor := database.NewPgTransactor(db)
	storeFactory := authStore.PgFactory{}

	var mailer authMailer.Mailer
	mailerParams := authMailer.Params{
		FromAddress:           config.mailerFromAddress,
		SendOTPRequestSubject: config.mailerOTPRequestSubject,
		SendOTPRequestContent: config.mailerOTPRequestContent,
	}
	switch config.mailer {
	case "resend":
		mailer = authMailer.NewResend(config.mailerResendAPIKey, config.mailerTimeout, mailerParams)
	case "log":
		mailer = authMailer.NewLog(mailerParams)
	default:
		fmt.Printf("unexpected mailer: %q\n", config.mailer)
		os.Exit(3)
	}

	service := authService.New(&authService.Params{
		StoreFactory:         &storeFactory,
		Mailer:               mailer,
		OTPDuration:          config.otpDuration,
		OTPMaxAttempts:       config.otpMaxAttempts,
		TokenManager:         tokenManager,
		TokenAccessDuration:  config.jwtAccessDuration,
		TokenRefreshDuration: config.jwtRefreshDuration,
		Transactor:           transactor,
	})

	mux := http.NewServeMux()
	handler := authHandler.New(service)
	handler.RegisterRequestOTP(mux)
	handler.RegisterConfirmOTP(mux)
	handler.RegisterRefreshAccessToken(mux)
	handler.RegisterListRefreshTokens(mux)
	handler.RegisterDeleteRefreshToken(mux)
	handler.RegisterDeleteUser(mux)

	server := &http.Server{
		Addr:         config.httpAddress,
		Handler:      authHandler.WithRequestID(authHandler.WithLogger(logger, mux)),
		ReadTimeout:  config.httpReadTimeout,
		WriteTimeout: config.httpWriteTimeout,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), config.logLevel),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Error("http server listen and serve", logging.Error(err))
				os.Exit(4)
			}
		}
	}()

	<-ctx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), config.httpReadTimeout+config.httpWriteTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("http server shutdown", logging.Error(err))
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

	databaseDataSourceName  string
	databaseMaxIdleConns    int
	databaseMaxOpenConns    int
	databaseConnMaxIdleTime time.Duration
	databaseConnMaxLifetime time.Duration

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

	databaseDataSourceName := os.Getenv("DATABASE_DATA_SOURCE_NAME")
	databaseMaxIdleConns, err := strconv.Atoi(os.Getenv("DATABASE_MAX_IDLE_CONNECTIONS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DATABASE_MAX_IDLE_CONNECTIONS: %w", err)
	}
	databaseMaxOpenConns, err := strconv.Atoi(os.Getenv("DATABASE_MAX_OPEN_CONNECTIONS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DATABASE_MAX_OPEN_CONNECTIONS: %w", err)
	}
	databaseConnMaxIdleTimeSeconds, err := strconv.Atoi(os.Getenv("DATABASE_CONNECTION_MAX_IDLE_TIME_SECONDS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DATABASE_CONNECTION_MAX_IDLE_TIME_SECONDS: %w", err)
	}
	databaseConnMaxLifetimeSeconds, err := strconv.Atoi(os.Getenv("DATABASE_CONNECTION_MAX_LIFE_TIME_SECONDS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DATABASE_CONNECTION_MAX_LIFE_TIME_SECONDS: %w", err)
	}

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

		databaseDataSourceName:  databaseDataSourceName,
		databaseMaxIdleConns:    databaseMaxIdleConns,
		databaseMaxOpenConns:    databaseMaxOpenConns,
		databaseConnMaxIdleTime: time.Duration(databaseConnMaxIdleTimeSeconds) * time.Second,
		databaseConnMaxLifetime: time.Duration(databaseConnMaxLifetimeSeconds) * time.Second,

		mailer:                  mailer,
		mailerResendAPIKey:      mailerResendAPIKey,
		mailerTimeout:           time.Duration(mailerTimeoutSeconds) * time.Second,
		mailerFromAddress:       mailerFromAddress,
		mailerOTPRequestSubject: mailerOTPRequestSubject,
		mailerOTPRequestContent: mailerOTPRequestContent,

		logLevel: slog.LevelInfo,
	}, nil
}
