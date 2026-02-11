package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lumen-paste/lumen/models"
)

// csrfToken retrieves the current CSRF token set by the CSRF middleware.
func csrfToken(c *gin.Context) string {
	if token, exists := c.Get("CSRFToken"); exists {
		return token.(string)
	}
	return ""
}

// Home renders the homepage with the paste creation form and public feed. (GET /)
func Home(c *gin.Context) {
	publicPastes, err := models.GetPublicRecent(12)
	if err != nil {
		publicPastes = []*models.PasteSummary{}
	}

	c.HTML(http.StatusOK, "home.html", gin.H{
		"Title":             "Lumen - Private Paste Bin",
		"ExpirationOptions": models.ExpirationOptions(),
		"PublicPastes":      publicPastes,
		"CSRFToken":         csrfToken(c),
	})
}
