package database

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	DB            *sql.DB
	cancelCleanup context.CancelFunc
)

// Initialize opens an SQLite connection with WAL mode, runs migrations,
// restricts file permissions, and starts background cleanup of expired pastes.
func Initialize(dbPath string) error {
	var err error
	DB, err = sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return err
	}

	DB.SetMaxOpenConns(1) // SQLite supports only one concurrent writer
	DB.SetMaxIdleConns(1)
	DB.SetConnMaxLifetime(time.Hour)

	if err := DB.Ping(); err != nil {
		return err
	}

	// Owner-only read/write (0600) — prevents other OS users from reading the DB
	if err := os.Chmod(dbPath, 0600); err != nil {
		log.Printf("Warning: could not set database file permissions: %v", err)
	}

	if err := runMigrations(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelCleanup = cancel
	go cleanupExpiredPastes(ctx)

	return nil
}

// Close cancels the background cleanup goroutine and closes the database.
func Close() error {
	if cancelCleanup != nil {
		cancelCleanup()
	}
	if DB != nil {
		return DB.Close()
	}
	return nil
}

func runMigrations() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS pastes (
			id TEXT PRIMARY KEY,
			title TEXT DEFAULT '',
			content TEXT NOT NULL,
			visibility TEXT NOT NULL DEFAULT 'unlisted',
			expiration DATETIME NOT NULL,
			burn_after_reading INTEGER NOT NULL DEFAULT 0,
			password_hash TEXT,
			admin_token TEXT NOT NULL,
			views INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			client_ip_hash TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS burned_pastes (
			id TEXT PRIMARY KEY,
			burned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pastes_expiration ON pastes(expiration)`,
		`CREATE INDEX IF NOT EXISTS idx_pastes_visibility ON pastes(visibility)`,
		`CREATE INDEX IF NOT EXISTS idx_pastes_created_at ON pastes(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_burned_pastes_burned_at ON burned_pastes(burned_at)`,
	}

	for _, migration := range migrations {
		if _, err := DB.Exec(migration); err != nil {
			return err
		}
	}

	return nil
}

// cleanupExpiredPastes periodically deletes pastes past their expiration time.
// Runs every 5 minutes until the context is cancelled during shutdown.
func cleanupExpiredPastes(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Cleanup goroutine stopped")
			return
		case <-ticker.C:
			result, err := DB.Exec("DELETE FROM pastes WHERE unixepoch(expiration) <= unixepoch('now')")
			if err != nil {
				log.Printf("Error cleaning up expired pastes: %v", err)
				continue
			}
			if affected, _ := result.RowsAffected(); affected > 0 {
				log.Printf("Cleaned up %d expired pastes", affected)
			}

			if _, err := DB.Exec("DELETE FROM burned_pastes WHERE burned_at <= datetime('now', '-45 days')"); err != nil {
				log.Printf("Error cleaning up burned_pastes markers: %v", err)
			}
		}
	}
}
