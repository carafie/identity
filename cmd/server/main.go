package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

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
		fmt.Println(err)
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
