package models

import (
	"database/sql"
	"strconv"
	"time"

	"github.com/lumen-paste/lumen/database"
	"github.com/lumen-paste/lumen/utils"
)

// Paste represents a stored paste with all database fields.
type Paste struct {
	ID               string
	Title            string
	Content          string
	Visibility       string // "public" or "unlisted"
	Expiration       time.Time
	BurnAfterReading bool
	PasswordHash     sql.NullString
	AdminToken       string
	Views            int
	CreatedAt        time.Time
	ClientIPHash     string
}

// PasteCreateInput holds validated form data for creating a new paste.
type PasteCreateInput struct {
	Title            string
	Content          string
	Visibility       string
	ExpiresIn        time.Duration
	BurnAfterReading bool
	Password         string
	ClientIP         string
	IDLength         int
	IPHashSecret     string
}

// PasteSummary is a lightweight projection for the public feed.
// Excludes content, admin tokens, password hashes, and IP hashes.
type PasteSummary struct {
	ID               string
	Title            string
	Views            int
	CreatedAt        time.Time
	BurnAfterReading bool
	IsProtected      bool
}

// IsPasswordProtected reports whether this paste requires a password.
func (p *PasteSummary) IsPasswordProtected() bool {
	return p.IsProtected
}

// ExpirationOptions returns the available expiration choices for the creation form.
func ExpirationOptions() []struct {
	Value string
	Label string
} {
	return []struct {
		Value string
		Label string
	}{
		{"10m", "10 Minutes"},
		{"1h", "1 Hour"},
		{"24h", "1 Day"},
		{"168h", "1 Week"},
		{"720h", "1 Month"},
	}
}

// Create stores a new paste. If a password is provided, the content is
// encrypted with AES-256-GCM and the password hash is stored alongside.
// Returns the created paste including its one-time admin token.
func Create(input PasteCreateInput) (*Paste, error) {
	idLength := input.IDLength
	if idLength <= 0 {
		idLength = 8
	}
	id, err := utils.GenerateID(idLength)
	if err != nil {
		return nil, err
	}

	adminToken, err := utils.GenerateToken()
	if err != nil {
		return nil, err
	}

	content := input.Content
	var passwordHash sql.NullString

	if input.Password != "" {
		encrypted, err := utils.EncryptContent(content, input.Password)
		if err != nil {
			return nil, err
		}
		content = encrypted

		hash, err := utils.HashPassword(input.Password)
		if err != nil {
			return nil, err
		}
		passwordHash = sql.NullString{String: hash, Valid: true}
	}

	expiration := time.Now().Add(input.ExpiresIn)
	clientIPHash := utils.HashIP(input.ClientIP, input.IPHashSecret)

	paste := &Paste{
		ID:               id,
		Title:            input.Title,
		Content:          content,
		Visibility:       input.Visibility,
		Expiration:       expiration,
		BurnAfterReading: input.BurnAfterReading,
		PasswordHash:     passwordHash,
		AdminToken:       adminToken,
		Views:            0,
		CreatedAt:        time.Now(),
		ClientIPHash:     clientIPHash,
	}

	_, err = database.DB.Exec(`
		INSERT INTO pastes (id, title, content, visibility, expiration, burn_after_reading, password_hash, admin_token, views, created_at, client_ip_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, paste.ID, paste.Title, paste.Content, paste.Visibility, paste.Expiration, paste.BurnAfterReading, paste.PasswordHash, paste.AdminToken, paste.Views, paste.CreatedAt, paste.ClientIPHash)

	if err != nil {
		return nil, err
	}

	return paste, nil
}

// GetByID retrieves a non-expired paste by its ID.
func GetByID(id string) (*Paste, error) {
	paste := &Paste{}
	err := database.DB.QueryRow(`
		SELECT id, title, content, visibility, expiration, burn_after_reading, password_hash, admin_token, views, created_at, client_ip_hash
		FROM pastes
		WHERE id = ? AND unixepoch(expiration) > unixepoch('now')
	`, id).Scan(
		&paste.ID, &paste.Title, &paste.Content, &paste.Visibility,
		&paste.Expiration, &paste.BurnAfterReading, &paste.PasswordHash,
		&paste.AdminToken, &paste.Views, &paste.CreatedAt, &paste.ClientIPHash,
	)

	if err != nil {
		return nil, err
	}

	return paste, nil
}

// DeleteBurnAndReturn atomically deletes a burn-after-reading paste and returns its data.
// Uses DELETE ... RETURNING to prevent race conditions where multiple concurrent readers
// could view a paste that should only be seen once. Returns sql.ErrNoRows if already burned.
func DeleteBurnAndReturn(id string) (*Paste, error) {
	tx, err := database.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	paste := &Paste{}
	err = tx.QueryRow(`
		DELETE FROM pastes WHERE id = ? AND burn_after_reading = 1
		RETURNING id, title, content, visibility, expiration, burn_after_reading,
		          password_hash, admin_token, views, created_at, client_ip_hash
	`, id).Scan(
		&paste.ID, &paste.Title, &paste.Content, &paste.Visibility,
		&paste.Expiration, &paste.BurnAfterReading, &paste.PasswordHash,
		&paste.AdminToken, &paste.Views, &paste.CreatedAt, &paste.ClientIPHash,
	)
	if err != nil {
		return nil, err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO burned_pastes (id, burned_at) VALUES (?, CURRENT_TIMESTAMP)`, id); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return paste, nil
}

// WasBurned reports whether this paste ID was previously consumed by burn-after-reading.
func WasBurned(id string) (bool, error) {
	var exists int
	err := database.DB.QueryRow(`SELECT 1 FROM burned_pastes WHERE id = ? LIMIT 1`, id).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// IncrementViews atomically increments the view counter for a paste.
func IncrementViews(id string) error {
	_, err := database.DB.Exec("UPDATE pastes SET views = views + 1 WHERE id = ?", id)
	return err
}

// Delete permanently removes a paste by ID.
func Delete(id string) error {
	_, err := database.DB.Exec("DELETE FROM pastes WHERE id = ?", id)
	return err
}

// DeleteWithToken deletes a paste only if the provided admin token matches.
// Returns sql.ErrNoRows if the paste doesn't exist or the token is invalid.
func DeleteWithToken(id, token string) error {
	result, err := database.DB.Exec("DELETE FROM pastes WHERE id = ? AND admin_token = ?", id, token)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetPublicRecent returns the most recent public pastes for the homepage feed.
// Only selects display-safe columns — no content, admin tokens, password hashes, or IP hashes.
func GetPublicRecent(limit int) ([]*PasteSummary, error) {
	rows, err := database.DB.Query(`
		SELECT id, title, views, created_at, burn_after_reading,
		       CASE WHEN password_hash IS NOT NULL AND password_hash != '' THEN 1 ELSE 0 END
		FROM pastes
		WHERE visibility = 'public' AND unixepoch(expiration) > unixepoch('now')
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pastes []*PasteSummary
	for rows.Next() {
		p := &PasteSummary{}
		err := rows.Scan(&p.ID, &p.Title, &p.Views, &p.CreatedAt, &p.BurnAfterReading, &p.IsProtected)
		if err != nil {
			return nil, err
		}
		pastes = append(pastes, p)
	}

	return pastes, nil
}

// IsPasswordProtected reports whether this paste requires a password to view.
func (p *Paste) IsPasswordProtected() bool {
	return p.PasswordHash.Valid
}

// VerifyPassword checks the password against the stored Argon2id hash.
// Returns true if the paste has no password or if the password matches.
func (p *Paste) VerifyPassword(password string) bool {
	if !p.PasswordHash.Valid {
		return true
	}
	return utils.VerifyPassword(password, p.PasswordHash.String)
}

// DecryptContent decrypts AES-256-GCM encrypted content using the given password.
// Returns plaintext content, or the original content if the paste isn't encrypted.
func (p *Paste) DecryptContent(password string) (string, error) {
	if !p.PasswordHash.Valid {
		return p.Content, nil
	}
	return utils.DecryptContent(p.Content, password)
}

// timeAgo formats a duration since t as a human-readable string (e.g. "3 hours ago").
func timeAgo(t time.Time) string {
	diff := time.Since(t)
	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return strconv.Itoa(mins) + " minutes ago"
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return strconv.Itoa(hours) + " hours ago"
	default:
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return strconv.Itoa(days) + " days ago"
	}
}

// TimeAgo returns when this paste was created (e.g. "5 minutes ago").
func (p *Paste) TimeAgo() string {
	return timeAgo(p.CreatedAt)
}

// TimeAgo returns when this paste was created (e.g. "2 hours ago").
func (p *PasteSummary) TimeAgo() string {
	return timeAgo(p.CreatedAt)
}

// ExpiresIn returns the remaining time until expiration (e.g. "23 hours").
func (p *Paste) ExpiresIn() string {
	diff := time.Until(p.Expiration)
	switch {
	case diff < time.Minute:
		return "less than a minute"
	case diff < time.Hour:
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 minute"
		}
		return strconv.Itoa(mins) + " minutes"
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour"
		}
		return strconv.Itoa(hours) + " hours"
	default:
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day"
		}
		return strconv.Itoa(days) + " days"
	}
}
