package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter tracks request timestamps per IP using a sliding window.
// Stored in memory — suitable for single-instance deployments.
type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a rate limiter with the given request limit and window.
// Starts a background goroutine to evict stale entries every minute.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, times := range rl.requests {
		var valid []time.Time
		for _, t := range times {
			if now.Sub(t) < rl.window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

// Allow returns true if the IP hasn't exceeded the rate limit within the current window.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	var valid []time.Time
	for _, t := range rl.requests[ip] {
		if now.Sub(t) < rl.window {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	valid = append(valid, now)
	rl.requests[ip] = valid
	return true
}

// CreateRateLimit returns middleware that limits paste creation (POST only) per IP.
func CreateRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	limiter := NewRateLimiter(limit, window)

	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		ip := c.ClientIP()
		if !limiter.Allow(ip) {
			c.HTML(http.StatusTooManyRequests, "error.html", gin.H{
				"Title":   "Rate Limited",
				"Message": "You've created too many pastes. Please try again later.",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ViewRateLimit returns middleware that limits paste viewing (all methods) per IP.
func ViewRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	limiter := NewRateLimiter(limit, window)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.Allow(ip) {
			c.HTML(http.StatusTooManyRequests, "error.html", gin.H{
				"Title":   "Rate Limited",
				"Message": "You've made too many requests. Please try again later.",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
