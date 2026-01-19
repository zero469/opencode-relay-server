package database

import (
	"database/sql"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func New(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := migrate(db); err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

func migrate(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		subdomain TEXT UNIQUE NOT NULL,
		auth_user TEXT NOT NULL DEFAULT '',
		auth_password TEXT NOT NULL DEFAULT '',
		online BOOLEAN DEFAULT FALSE,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_devices_subdomain ON devices(subdomain);

	CREATE TABLE IF NOT EXISTS verification_codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL,
		code TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		used BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_verification_codes_email ON verification_codes(email);
	`

	_, err := db.Exec(schema)
	if err != nil {
		return err
	}

	// Migration: Add auth columns if they don't exist (for existing databases)
	migrations := []string{
		`ALTER TABLE devices ADD COLUMN auth_user TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN auth_password TEXT NOT NULL DEFAULT ''`,
	}
	for _, m := range migrations {
		// Ignore errors (column may already exist)
		db.Exec(m)
	}

	return nil
}
