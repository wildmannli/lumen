package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/lumen-paste/lumen/config"
	"github.com/lumen-paste/lumen/models"
	"github.com/lumen-paste/lumen/utils"
)

// CreatePaste validates form input and stores a new paste. (POST /)
func CreatePaste(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		title := c.PostForm("title")
		content := c.PostForm("content")
		visibility := c.PostForm("visibility")
		expiresIn := c.PostForm("expires_in")
		password := c.PostForm("password")
		burnAfterReading := c.PostForm("burn_after_reading") == "on"

		if len(title) > 200 {
			title = title[:200]
		}

		if content == "" {
			c.HTML(http.StatusBadRequest, "home.html", gin.H{
				"Title":             "Lumen - Private Paste Bin",
				"Error":             "Content is required",
				"ExpirationOptions": models.ExpirationOptions(),
				"CSRFToken":         csrfToken(c),
			})
			return
		}

		if int64(len(content)) > cfg.MaxPasteSize {
			c.HTML(http.StatusBadRequest, "home.html", gin.H{
				"Title":             "Lumen - Private Paste Bin",
				"Error":             fmt.Sprintf("Content exceeds maximum size of %d KB", cfg.MaxPasteSize/1024),
				"ExpirationOptions": models.ExpirationOptions(),
				"CSRFToken":         csrfToken(c),
			})
			return
		}

		if password != "" && len(password) < 8 {
			c.HTML(http.StatusBadRequest, "home.html", gin.H{
				"Title":             "Lumen - Private Paste Bin",
				"Error":             "Password must be at least 8 characters",
				"ExpirationOptions": models.ExpirationOptions(),
				"CSRFToken":         csrfToken(c),
			})
			return
		}

		if visibility != "public" && visibility != "unlisted" {
			visibility = "unlisted"
		}

		duration, err := time.ParseDuration(expiresIn)
		if err != nil || duration <= 0 {
			duration = cfg.DefaultExpiry
		}
		if duration > cfg.MaxExpiry {
			duration = cfg.MaxExpiry
		}

		paste, err := models.Create(models.PasteCreateInput{
			Title:            title,
			Content:          content,
			Visibility:       visibility,
			ExpiresIn:        duration,
			BurnAfterReading: burnAfterReading,
			Password:         password,
			ClientIP:         c.ClientIP(),
			IDLength:         cfg.IDLength,
			IPHashSecret:     cfg.IPHashSecret,
		})
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Title":   "Error",
				"Message": "Failed to create paste. Please try again.",
			})
			return
		}

		// Admin token is shown once via query string; not stored in cookies or sessions
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/p/%s?admin=%s", paste.ID, paste.AdminToken))
	}
}

// ViewPaste displays a paste with rendered markdown and source tabs. (GET /p/:id)
// Handles password gating, burn-after-reading, admin banners, and syntax highlighting.
func ViewPaste(c *gin.Context) {
	id := c.Param("id")
	adminToken := c.Query("admin")

	paste, err := models.GetByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			if burned, burnErr := models.WasBurned(id); burnErr == nil && burned {
				c.HTML(http.StatusNotFound, "error.html", gin.H{
					"Title":   "Already Burned",
					"Message": "This paste has already been viewed and destroyed.",
				})
				return
			}
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"Title":   "Not Found",
				"Message": "This paste does not exist or has expired.",
			})
			return
		}
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Title":   "Error",
			"Message": "Failed to retrieve paste.",
		})
		return
	}

	if adminToken != "" && adminToken != paste.AdminToken {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"Title":   "Forbidden",
			"Message": "Invalid admin token.",
		})
		return
	}

	isAdmin := adminToken == paste.AdminToken

	if paste.IsPasswordProtected() {
		data := gin.H{
			"Title":     "Password Required",
			"PasteID":   paste.ID,
			"CSRFToken": csrfToken(c),
		}
		if isAdmin {
			data["AdminToken"] = paste.AdminToken
		}
		c.HTML(http.StatusOK, "password.html", data)
		return
	}

	// Burn-after-reading: atomic DELETE ... RETURNING ensures only one reader succeeds
	if paste.BurnAfterReading && !isAdmin {
		burnPaste, err := models.DeleteBurnAndReturn(id)
		if err != nil {
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"Title":   "Already Burned",
				"Message": "This paste has already been viewed and destroyed.",
			})
			return
		}
		paste = burnPaste
	}

	renderedContent, err := utils.RenderMarkdown(paste.Content)
	if err != nil {
		renderedContent = utils.EscapeHTML(paste.Content)
	}

	// Don't count admin visits or burned pastes in view stats
	if !isAdmin && !paste.BurnAfterReading {
		if err := models.IncrementViews(paste.ID); err != nil {
			log.Printf("Warning: failed to increment views for paste %s: %v", paste.ID, err)
		}
	}

	data := gin.H{
		"Title":            paste.Title,
		"Paste":            paste,
		"RenderedContent":  renderedContent,
		"RawContent":       paste.Content,
		"ShowAdminLink":    isAdmin,
		"BurnAfterReading": paste.BurnAfterReading,
	}

	// Syntax highlighting from file extension in title (e.g. "schema.sql" → SQL)
	if hl, ok := utils.HighlightCode(paste.Content, paste.Title); ok {
		data["HighlightedSource"] = hl
		data["Language"] = utils.DetectLanguage(paste.Title)
	}

	// Admin-only: share link & delete link shown once after paste creation
	if isAdmin {
		data["AdminToken"] = paste.AdminToken
		scheme := "http"
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		data["PasteURL"] = fmt.Sprintf("%s://%s/p/%s", scheme, c.Request.Host, paste.ID)
		data["DeleteURL"] = fmt.Sprintf("%s://%s/p/%s/delete/%s", scheme, c.Request.Host, paste.ID, paste.AdminToken)
	}

	if paste.BurnAfterReading && !isAdmin {
		data["BurnWarning"] = true
	}

	c.HTML(http.StatusOK, "view.html", data)
}

// UnlockPaste verifies the password, decrypts content, and renders the paste. (POST /p/:id/unlock)
func UnlockPaste(c *gin.Context) {
	id := c.Param("id")
	password := c.PostForm("password")
	adminToken := c.PostForm("admin_token")

	paste, err := models.GetByID(id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"Title":   "Not Found",
			"Message": "This paste does not exist or has expired.",
		})
		return
	}

	if adminToken != "" && adminToken != paste.AdminToken {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"Title":   "Forbidden",
			"Message": "Invalid admin token.",
		})
		return
	}

	isAdmin := adminToken == paste.AdminToken

	if !paste.VerifyPassword(password) {
		data := gin.H{
			"Title":     "Password Required",
			"PasteID":   paste.ID,
			"Error":     "Incorrect password",
			"CSRFToken": csrfToken(c),
		}
		if isAdmin {
			data["AdminToken"] = paste.AdminToken
		}
		c.HTML(http.StatusUnauthorized, "password.html", data)
		return
	}

	if paste.BurnAfterReading && !isAdmin {
		burnPaste, err := models.DeleteBurnAndReturn(id)
		if err != nil {
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"Title":   "Already Burned",
				"Message": "This paste has already been viewed and destroyed.",
			})
			return
		}
		paste = burnPaste
	}

	content, err := paste.DecryptContent(password)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Title":   "Error",
			"Message": "Failed to decrypt paste.",
		})
		return
	}

	renderedContent, err := utils.RenderMarkdown(content)
	if err != nil {
		renderedContent = utils.EscapeHTML(content)
	}

	if !isAdmin && !paste.BurnAfterReading {
		if err := models.IncrementViews(paste.ID); err != nil {
			log.Printf("Warning: failed to increment views for paste %s: %v", paste.ID, err)
		}
	}

	data := gin.H{
		"Title":            paste.Title,
		"Paste":            paste,
		"RenderedContent":  renderedContent,
		"RawContent":       content,
		"ShowAdminLink":    isAdmin,
		"BurnAfterReading": paste.BurnAfterReading,
	}

	if hl, ok := utils.HighlightCode(content, paste.Title); ok {
		data["HighlightedSource"] = hl
		data["Language"] = utils.DetectLanguage(paste.Title)
	}

	if isAdmin {
		data["AdminToken"] = paste.AdminToken
		scheme := "http"
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		data["PasteURL"] = fmt.Sprintf("%s://%s/p/%s", scheme, c.Request.Host, paste.ID)
		data["DeleteURL"] = fmt.Sprintf("%s://%s/p/%s/delete/%s", scheme, c.Request.Host, paste.ID, paste.AdminToken)
	}

	if paste.BurnAfterReading && !isAdmin {
		data["BurnWarning"] = true
	}

	c.HTML(http.StatusOK, "view.html", data)
}

// RawPaste returns plaintext paste content. (GET /p/:id/raw)
func RawPaste(c *gin.Context) {
	id := c.Param("id")

	paste, err := models.GetByID(id)
	if err != nil {
		c.String(http.StatusNotFound, "Paste not found or expired")
		return
	}

	if paste.IsPasswordProtected() {
		c.String(http.StatusForbidden, "This paste is password protected")
		return
	}

	if paste.BurnAfterReading {
		burnPaste, err := models.DeleteBurnAndReturn(id)
		if err != nil {
			c.String(http.StatusNotFound, "This paste has already been viewed and burned")
			return
		}
		paste = burnPaste
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", "inline; filename=\"paste.txt\"")
	c.String(http.StatusOK, paste.Content)
}

// ForkPaste renders the creation form pre-filled with an existing paste's content. (GET /p/:id/fork)
// Blocked for password-protected and burn-after-reading pastes.
func ForkPaste(c *gin.Context) {
	id := c.Param("id")

	paste, err := models.GetByID(id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"Title":   "Not Found",
			"Message": "This paste does not exist or has expired.",
		})
		return
	}

	if paste.IsPasswordProtected() {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"Title":   "Cannot Fork",
			"Message": "Password-protected pastes cannot be forked.",
		})
		return
	}

	if paste.BurnAfterReading {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"Title":   "Cannot Fork",
			"Message": "Burn-after-reading pastes cannot be forked.",
		})
		return
	}

	publicPastes, _ := models.GetPublicRecent(12)

	c.HTML(http.StatusOK, "home.html", gin.H{
		"Title":             "Fork Paste - Lumen",
		"ExpirationOptions": models.ExpirationOptions(),
		"PublicPastes":      publicPastes,
		"CSRFToken":         csrfToken(c),
		"ForkTitle":         paste.Title,
		"ForkContent":       paste.Content,
	})
}

// DownloadPaste serves paste content as a file attachment. (GET /p/:id/download)
// Uses the paste title as filename; sanitizes it to prevent path traversal.
func DownloadPaste(c *gin.Context) {
	id := c.Param("id")

	paste, err := models.GetByID(id)
	if err != nil {
		c.String(http.StatusNotFound, "Paste not found or expired")
		return
	}

	if paste.IsPasswordProtected() {
		c.String(http.StatusForbidden, "This paste is password protected")
		return
	}

	if paste.BurnAfterReading {
		burnPaste, err := models.DeleteBurnAndReturn(id)
		if err != nil {
			c.String(http.StatusNotFound, "This paste has already been viewed and burned")
			return
		}
		paste = burnPaste
	}

	filename := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '\x00' || unicode.IsControl(r) {
			return -1
		}
		return r
	}, paste.Title)
	filename = filepath.Base(filename)
	if filename == "" || filename == "." {
		filename = "paste.txt"
	}
	if filepath.Ext(filename) == "" {
		filename += ".txt"
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.String(http.StatusOK, paste.Content)
}

// ConfirmDelete shows the delete confirmation page. (GET /p/:id/delete/:token)
func ConfirmDelete(c *gin.Context) {
	id := c.Param("id")
	token := c.Param("token")

	paste, err := models.GetByID(id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"Title":   "Not Found",
			"Message": "This paste does not exist or has expired.",
		})
		return
	}

	if paste.AdminToken != token {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"Title":   "Forbidden",
			"Message": "Invalid admin token.",
		})
		return
	}

	c.HTML(http.StatusOK, "delete.html", gin.H{
		"Title":     "Delete Paste",
		"PasteID":   paste.ID,
		"Token":     token,
		"CSRFToken": csrfToken(c),
	})
}

// ExecuteDelete permanently deletes a paste after token validation. (POST /p/:id/delete/:token)
func ExecuteDelete(c *gin.Context) {
	id := c.Param("id")
	token := c.Param("token")

	err := models.DeleteWithToken(id, token)
	if err != nil {
		if err == sql.ErrNoRows {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"Title":   "Forbidden",
				"Message": "Invalid admin token.",
			})
			return
		}
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Title":   "Error",
			"Message": "Failed to delete paste.",
		})
		return
	}

	c.HTML(http.StatusOK, "deleted.html", gin.H{
		"Title": "Paste Deleted",
	})
}
