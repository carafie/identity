package database

import (
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const DriverName = "pgx"

type DB struct {
	Pool *sql.DB
}

func Open(config Config) (*DB, error) {
	pool, err := sql.Open(DriverName, config.DataSourceName)
	if err != nil {
		return nil, err
	}

	pool.SetMaxIdleConns(config.MaxIdleConns)
	pool.SetMaxOpenConns(config.MaxOpenConns)
	pool.SetConnMaxIdleTime(config.ConnMaxIdleTime)
	pool.SetConnMaxLifetime(config.ConnMaxLifetime)

	if err := pool.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping: %w", err)
	}

	return &DB{Pool: pool}, nil
}

func (db *DB) Close() error {
	return db.Pool.Close()
}
