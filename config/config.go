package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application settings, loaded from environment variables.
type Config struct {
	Port           string
	Environment    string
	TrustedProxies []string
	DatabasePath   string

	MaxPasteSize  int64
	DefaultExpiry time.Duration
	MaxExpiry     time.Duration
	IDLength      int

	CreateRateLimit int           // max paste creations per window per IP
	ViewRateLimit   int           // max paste views per window per IP
	RateWindow      time.Duration // sliding window duration for rate limits

	IPHashSecret string // HMAC key for IP hashing; set in production to prevent rainbow tables
}

// Load reads configuration from environment variables, applying defaults where unset.
func Load() *Config {
	return &Config{
		Port:            getEnv("PORT", "8080"),
		Environment:     normalizeEnvironment(getEnv("ENVIRONMENT", "development")),
		TrustedProxies:  getEnvSlice("TRUSTED_PROXIES"),
		DatabasePath:    getEnv("DATABASE_PATH", "./lumen.db"),
		MaxPasteSize:    getEnvInt64("MAX_PASTE_SIZE", 512*1024), // 512 KB
		DefaultExpiry:   getEnvDuration("DEFAULT_EXPIRY", 24*time.Hour),
		MaxExpiry:       getEnvDuration("MAX_EXPIRY", 30*24*time.Hour), // 1 month
		IDLength:        getEnvInt("ID_LENGTH", 8),
		CreateRateLimit: getEnvInt("CREATE_RATE_LIMIT", 10),
		ViewRateLimit:   getEnvInt("VIEW_RATE_LIMIT", 100),
		RateWindow:      getEnvDuration("RATE_WINDOW", time.Hour),
		IPHashSecret:    getEnv("IP_HASH_SECRET", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvSlice(key string) []string {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		var result []string
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}
	return nil
}

func normalizeEnvironment(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if i := strings.Index(normalized, "#"); i >= 0 {
		normalized = strings.TrimSpace(normalized[:i])
	}
	if normalized == "" {
		return "development"
	}
	return normalized
}
