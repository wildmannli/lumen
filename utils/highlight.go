package utils

import (
	"bytes"

	"github.com/alecthomas/chroma/v2"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
)

// HighlightCode returns syntax-highlighted HTML for the given code.
// Language is detected from the filename/title extension (e.g. "schema.sql" → SQL).
// Returns the highlighted HTML and true if a language was detected,
// or empty string and false to fall back to plain text.
func HighlightCode(code, filename string) (string, bool) {
	if filename == "" {
		return "", false
	}

	lexer := lexers.Match(filename)
	if lexer == nil {
		return "", false
	}
	lexer = chroma.Coalesce(lexer)

	style := styles.Get("monokai")
	if style == nil {
		style = styles.Fallback
	}

	formatter := chromahtml.New(
		chromahtml.WithLineNumbers(true),
		chromahtml.LineNumbersInTable(true),
		chromahtml.WithClasses(false),
		chromahtml.TabWidth(4),
	)

	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return "", false
	}

	var buf bytes.Buffer
	if err := formatter.Format(&buf, style, iterator); err != nil {
		return "", false
	}

	return buf.String(), true
}

// DetectLanguage returns the display name of the language for a filename.
// Returns empty string if no language is detected.
func DetectLanguage(filename string) string {
	if filename == "" {
		return ""
	}
	lexer := lexers.Match(filename)
	if lexer == nil {
		return ""
	}
	return lexer.Config().Name
}
