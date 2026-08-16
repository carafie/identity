package databasetest

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/carafie/identity"
	"github.com/carafie/identity/internal/database"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/testcontainers/testcontainers-go"
	containerLog "github.com/testcontainers/testcontainers-go/log"
	pgContainer "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const (
	pgImage    = "postgres:18.6-alpine3.24"
	pgDatabase = "database"
	pgUsername = "username"
	pgPassword = "password"
)

func Open(ctx context.Context) (*database.DB, func(), error) {
	logger := log.New(io.Discard, "", 0)
	containerLog.SetDefault(logger)

	container, err := pgContainer.Run(ctx,
		pgImage,
		pgContainer.WithDatabase(pgDatabase),
		pgContainer.WithUsername(pgUsername),
		pgContainer.WithPassword(pgPassword),
		pgContainer.BasicWaitStrategies(),
	)
	close := func() {
		testcontainers.TerminateContainer(container)
	}
	if err != nil {
		return nil, close, fmt.Errorf("failed to run container: %w", err)
	}

	dsn, err := container.ConnectionString(ctx)
	if err != nil {
		return nil, close, fmt.Errorf("failed to parse data source name: %w", err)
	}
	db, err := database.Open(database.Config{DataSourceName: dsn})
	if err != nil {
		return nil, close, fmt.Errorf("failed to open database: %w", err)
	}
	close = func() {
		db.Close()
		testcontainers.TerminateContainer(container)
	}

	if err := runMigrations(db); err != nil {
		return nil, close, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, close, nil
}

func runMigrations(db *database.DB) error {
	dbDriver, err := postgres.WithInstance(db.Pool, &postgres.Config{})
	if err != nil {
		return err
	}
	sourceDriver, err := iofs.New(identity.FS, identity.MigrationsPath)
	if err != nil {
		return err
	}
	defer sourceDriver.Close()
	m, err := migrate.NewWithInstance("iofs", sourceDriver, database.DriverName, dbDriver)
	if err != nil {
		return err
	}
	return m.Up()
}
