package utils

import (
	"bytes"
	"html"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	gmhtml "github.com/yuin/goldmark/renderer/html"
)

var (
	md       goldmark.Markdown
	sanitize *bluemonday.Policy
)

func init() {
	md = goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,
			extension.Table,
			extension.Strikethrough,
			extension.TaskList,
		),
		goldmark.WithRendererOptions(
			gmhtml.WithHardWraps(),
			gmhtml.WithXHTML(),
		),
	)

	// UGC policy: allows safe elements (p, a, img, code, etc.)
	// while stripping script, iframe, object, embed, form tags.
	sanitize = bluemonday.UGCPolicy()
}

// RenderMarkdown converts GFM markdown to sanitized HTML.
// Sanitization is defense-in-depth — Goldmark already escapes raw HTML.
func RenderMarkdown(content string) (string, error) {
	var buf bytes.Buffer
	if err := md.Convert([]byte(content), &buf); err != nil {
		return "", err
	}
	return sanitize.Sanitize(buf.String()), nil
}

// EscapeHTML escapes HTML entities as a fallback when markdown rendering fails.
func EscapeHTML(content string) string {
	return html.EscapeString(content)
}
