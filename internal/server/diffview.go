package server

import (
	"html/template"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// diffHTML redacts and escapes a unified diff and wraps each line in a span
// whose class says what it is (added, removed, hunk header, file header or
// context), so the stylesheet can colour it. Colour is never the only cue:
// the +/- prefix stays in the text.
func diffHTML(s string) template.HTML {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(redact.String(s), "\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		class := "d-ctx"
		switch {
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
			class = "d-file"
		case strings.HasPrefix(line, "@@"):
			class = "d-hunk"
		case strings.HasPrefix(line, "+"):
			class = "d-add"
		case strings.HasPrefix(line, "-"):
			class = "d-del"
		}
		if line == "" {
			line = " " // keep blank context lines one line tall
		}
		b.WriteString(`<span class="dl ` + class + `">` + template.HTMLEscapeString(line) + `</span>`)
	}
	return template.HTML(b.String()) // #nosec: every line is escaped above
}
