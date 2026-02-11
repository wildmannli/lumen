package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders sets strict security headers on every response.
// Notable: script-src 'none' means zero JavaScript — the entire app is server-rendered.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		c.Header("X-XSS-Protection", "0") // deprecated; disabled to avoid false positives

		// HSTS: only sent when behind TLS (direct or via proxy)
		if isHTTPSRequest(c) {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Prevent browsers from caching paste content
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		c.Next()
	}
}

func isHTTPSRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}

	// Handles common proxy formats: "https" or "https,http".
	for _, part := range strings.Split(c.GetHeader("X-Forwarded-Proto"), ",") {
		if strings.EqualFold(strings.TrimSpace(part), "https") {
			return true
		}
	}

	// RFC 7239 Forwarded header (e.g., "for=1.2.3.4;proto=https;host=...").
	for _, entry := range strings.Split(c.GetHeader("Forwarded"), ",") {
		for _, directive := range strings.Split(entry, ";") {
			directive = strings.TrimSpace(directive)
			if len(directive) >= 6 && strings.EqualFold(directive[:6], "proto=") {
				proto := strings.Trim(directive[6:], "\"")
				if strings.EqualFold(strings.TrimSpace(proto), "https") {
					return true
				}
			}
		}
	}

	return false
}
