package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	csrfCookieName = "_csrf_token"
	csrfFormField  = "_csrf_token"
	csrfTokenLen   = 32
)

// CSRF protects against Cross-Site Request Forgery using Double Submit Cookie.
//
// GET/HEAD: ensures a CSRF token cookie exists; stores it in context for templates.
// POST: validates the form _csrf_token field matches the cookie; rejects with 403
// if missing or mismatched. Regenerates the token after each successful POST.
func CSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead:
			token, err := c.Cookie(csrfCookieName)
			if err != nil || token == "" {
				token, err = generateCSRFToken()
				if err != nil {
					c.AbortWithStatus(http.StatusInternalServerError)
					return
				}
				setCSRFCookie(c, token)
			}
			c.Set("CSRFToken", token)

		case http.MethodPost:
			cookieToken, err := c.Cookie(csrfCookieName)
			if err != nil || cookieToken == "" {
				c.HTML(http.StatusForbidden, "error.html", gin.H{
					"Title":   "Forbidden",
					"Message": "CSRF validation failed. Please go back and try again.",
				})
				c.Abort()
				return
			}

			formToken := c.PostForm(csrfFormField)
			if formToken == "" || subtle.ConstantTimeCompare([]byte(cookieToken), []byte(formToken)) != 1 {
				c.HTML(http.StatusForbidden, "error.html", gin.H{
					"Title":   "Forbidden",
					"Message": "CSRF validation failed. Please go back and try again.",
				})
				c.Abort()
				return
			}

			newToken, err := generateCSRFToken()
			if err == nil {
				setCSRFCookie(c, newToken)
				c.Set("CSRFToken", newToken)
			}
		}

		c.Next()
	}
}

// generateCSRFToken produces a 32-byte cryptographically random hex string.
func generateCSRFToken() (string, error) {
	bytes := make([]byte, csrfTokenLen)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// setCSRFCookie writes the token as a SameSite=Strict, HttpOnly, session cookie.
func setCSRFCookie(c *gin.Context, token string) {
	secure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(csrfCookieName, token, 0, "/", "", secure, true)
}
