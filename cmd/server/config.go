package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"
)

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
	p := &envVarParser{}
	return &config{
		httpAddress:      p.string("HTTP_ADDRESS"),
		httpReadTimeout:  p.durationSeconds("HTTP_READ_TIMEOUT_SECONDS"),
		httpWriteTimeout: p.durationSeconds("HTTP_WRITE_TIMEOUT_SECONDS"),

		otpDuration:    p.durationSeconds("OTP_DURATION_SECONDS"),
		otpMaxAttempts: p.int("OTP_MAX_ATTEMPTS"),

		jwtPublicKey:       p.ed25519PublicKey("JWT_PUBLIC_KEY_FILE"),
		jwtPrivateKey:      p.ed25519PrivateKey("JWT_PRIVATE_KEY_FILE"),
		jwtAccessDuration:  p.durationSeconds("JWT_ACCESS_DURATION_SECONDS"),
		jwtRefreshDuration: p.durationSeconds("JWT_REFRESH_DURATION_SECONDS"),

		databaseDataSourceName:  p.string("DATABASE_DATA_SOURCE_NAME"),
		databaseMaxIdleConns:    p.int("DATABASE_MAX_IDLE_CONNECTIONS"),
		databaseMaxOpenConns:    p.int("DATABASE_MAX_OPEN_CONNECTIONS"),
		databaseConnMaxIdleTime: p.durationSeconds("DATABASE_CONNECTION_MAX_IDLE_TIME_SECONDS"),
		databaseConnMaxLifetime: p.durationSeconds("DATABASE_CONNECTION_MAX_LIFE_TIME_SECONDS"),

		mailer:                  p.string("MAILER"),
		mailerResendAPIKey:      p.string("MAILER_RESEND_API_KEY", false),
		mailerTimeout:           p.durationSeconds("MAILER_TIMEOUT_SECONDS"),
		mailerFromAddress:       p.string("MAILER_FROM_ADDRESS"),
		mailerOTPRequestSubject: p.string("MAILER_OTP_REQUEST_SUBJECT"),
		mailerOTPRequestContent: p.string("MAILER_OTP_REQUEST_CONTENT"),

		logLevel: slog.LevelInfo,
	}, errors.Join(p.errs...)
}

type envVarParser struct {
	errs []error
}

func (p *envVarParser) string(key string, required ...bool) string {
	value := os.Getenv(key)
	if value == "" {
		if p.isRequired(required...) {
			p.missingEnvVar(key)
		}
		return ""
	}
	return value
}

func (p *envVarParser) int(key string, required ...bool) int {
	value := os.Getenv(key)
	if value == "" {
		if p.isRequired(required...) {
			p.missingEnvVar(key)
		}
		return 0
	}

	valueInt, err := strconv.Atoi(value)
	if err != nil {
		p.parseErr(key, err)
		return 0
	}
	return valueInt
}

func (p *envVarParser) durationSeconds(key string, required ...bool) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		if p.isRequired(required...) {
			p.missingEnvVar(key)
		}
		return 0
	}

	valueInt, err := strconv.Atoi(value)
	if err != nil {
		p.parseErr(key, err)
		return 0
	}
	return time.Duration(valueInt) * time.Second
}

func (p *envVarParser) ed25519PublicKey(key string, required ...bool) ed25519.PublicKey {
	value := os.Getenv(key)
	if value == "" {
		if p.isRequired(required...) {
			p.missingEnvVar(key)
		}
		return nil
	}

	bytes, err := os.ReadFile(value)
	if err != nil {
		p.parseErr(key, err)
		return nil
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		p.parseErr(key, fmt.Errorf("failed to decode PEM block"))
		return nil
	}
	publicKeyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		p.parseErr(key, err)
		return nil
	}
	publicKey, ok := publicKeyAny.(ed25519.PublicKey)
	if !ok {
		p.parseErr(key, fmt.Errorf("key is not Ed25519 public key"))
		return nil
	}
	return publicKey
}

func (p *envVarParser) ed25519PrivateKey(key string, required ...bool) ed25519.PrivateKey {
	value := os.Getenv(key)
	if value == "" {
		if p.isRequired(required...) {
			p.missingEnvVar(key)
		}
		return nil
	}

	bytes, err := os.ReadFile(value)
	if err != nil {
		p.parseErr(key, err)
		return nil
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		p.parseErr(key, fmt.Errorf("failed to decode PEM block"))
		return nil
	}
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		p.parseErr(key, err)
		return nil
	}
	privateKey, ok := privateKeyAny.(ed25519.PrivateKey)
	if !ok {
		p.parseErr(key, fmt.Errorf("key is not Ed25519 private key"))
		return nil
	}
	return privateKey
}

func (p *envVarParser) isRequired(required ...bool) bool {
	return len(required) == 0 || (len(required) > 0 && required[0])
}

func (p *envVarParser) missingEnvVar(key string) {
	p.errs = append(p.errs, fmt.Errorf("missing required environment variable %s", key))
}

func (p *envVarParser) parseErr(key string, err error) {
	p.errs = append(p.errs, fmt.Errorf("failed to parse environment variable %s: %w", key, err))
}
