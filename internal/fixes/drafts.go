package fixes

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

const diffContext = 3

var backtickRe = regexp.MustCompile("`([^`]+)`")

// serverTraitsFile is the new server-side module proposed by trait drafts.
const serverTraitsFile = "server/flagsmith-traits.js"

const serverTraitsSource = `// Sets Flagsmith traits from server-side truth. Never copy a trait value from the request.
const flagsmith = require("flagsmith-nodejs");
const entitlements = require("./entitlements"); // your source of truth for what each user is entitled to

module.exports = function mountTraitRoutes(app, requireSession) {
  app.post("/api/flagsmith/traits/:name", requireSession, async (req, res) => {
    const value = entitlements.traitValue(req.user.id, req.params.name);
    if (value === undefined) return res.status(404).end();
    await flagsmith.getIdentityFlags(String(req.user.id), { [req.params.name]: value });
    res.status(204).end();
  });
};
`

// DefaultDraft returns the deterministic PR-draft generator. For client-side
// trait writes it produces a real unified diff (read from repoDir) that
// moves each setTrait behind a server endpoint, plus the server module.
func DefaultDraft(repoDir string) DraftFunc {
	return func(f model.Finding, impact []model.ImpactItem) string {
		switch classify(f.Type) {
		case fixClientTraits:
			return traitDraft(repoDir, impact)
		case fixReroll:
			return rerollDraft(f)
		default:
			return serverOnlyDraft(f, impact)
		}
	}
}

func traitDraft(repoDir string, impact []model.ImpactItem) string {
	var b strings.Builder
	b.WriteString("Move client-side trait writes to your server\n\n")
	b.WriteString("Flagsmith lets any browser set its own traits, so a segment that gates on a client-set trait can be\n")
	b.WriteString("forged by anyone. Once \"Allow client SDKs to set user traits\" is off, the trait must be set by your\n")
	b.WriteString("server from data it trusts (entitlements, billing), never from the request.\n\n")
	edits := map[string][]lineEdit{}
	for _, it := range impact {
		if it.Breaks {
			edits[it.File] = append(edits[it.File], lineEdit{line: it.Line, repl: traitReplacement(it)})
		}
	}
	if len(edits) == 0 {
		b.WriteString("No client-side setTrait calls that gate a segment were found in the scanned repo; make sure every\ntrait used by a segment is written by server code.\n")
		return b.String()
	}
	files := make([]string, 0, len(edits))
	for f := range edits {
		files = append(files, f)
	}
	sort.Strings(files)
	var jsTouched bool
	for _, rel := range files {
		d, err := fileDiff(repoDir, rel, edits[rel])
		if err != nil {
			fmt.Fprintf(&b, "(could not produce a diff for %s: %v)\n", rel, err)
			continue
		}
		jsTouched = jsTouched || isJSFamily(rel)
		b.WriteString(d)
	}
	if jsTouched {
		b.WriteString("\nServer side (new file):\n")
		b.WriteString(newFileDiff(serverTraitsFile, serverTraitsSource))
	}
	return b.String()
}

func traitReplacement(it model.ImpactItem) []string {
	name := ""
	if m := backtickRe.FindStringSubmatch(it.Message); m != nil && !strings.Contains(m[1], " ") {
		name = m[1]
	}
	if isJSFamily(it.File) {
		path := "/api/flagsmith/traits"
		note := "// Moved server-side: your server sets this trait after checking entitlement."
		if name != "" {
			path += "/" + name
			note = fmt.Sprintf("// Moved server-side: your server sets the %q trait after checking entitlement.", name)
		}
		return []string{note, `fetch("` + path + `", { method: "POST", credentials: "same-origin" });`}
	}
	return []string{"// Removed: set this trait from your server with the Flagsmith server SDK."}
}

func isJSFamily(file string) bool {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm":
		return true
	}
	return false
}

func serverOnlyDraft(f model.Finding, impact []model.ImpactItem) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Stop shipping `%s` to browsers\n\n", f.Subject)
	b.WriteString("Flagsmith serves every non-server-only flag to anyone holding the client key. After the flag is marked\n")
	b.WriteString("Server-side only, client SDKs no longer receive it, so:\n\n")
	b.WriteString("1. Move the value into your server-side config or secret manager.\n")
	b.WriteString("2. Read it on your server (server SDK or environment document), not in browser code.\n")
	b.WriteString("3. Remove the value from the Flagsmith flag once nothing reads it remotely.\n")
	if f.Type == model.FSecretExposed {
		b.WriteString("4. Rotate the secret: it has already been public.\n")
	}
	if len(impact) > 0 {
		b.WriteString("\nClient code that reads the flag today:\n")
		for _, it := range impact {
			fmt.Fprintf(&b, "- %s:%d  %s\n", it.File, it.Line, it.Snippet)
		}
	}
	return b.String()
}

func rerollDraft(f model.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Assign identifiers for `%s` on the server\n\n", f.Subject)
	b.WriteString("Percentage rollouts, variants and experiments bucket users by their Flagsmith identifier. When the\n")
	b.WriteString("client picks that identifier, a user can re-roll until they land in the bucket they want.\n\n")
	b.WriteString("1. Generate the identifier on the server (for example an HMAC of the user id or a signed session id).\n")
	b.WriteString("2. Pass it to the client in the page or API response; never let the client choose or change it.\n")
	b.WriteString("3. If an experiment ran with client-chosen identifiers, restart it after the fix: its results are biased.\n")
	return b.String()
}

// lineEdit replaces one source line (1-based) with new lines.
type lineEdit struct {
	line int
	repl []string
}

// fileDiff builds a unified diff of the edits against repoDir/rel. The
// replacement lines inherit the indentation and line endings of the line
// they replace.
func fileDiff(repoDir, rel string, edits []lineEdit) (string, error) {
	raw, err := os.ReadFile(filepath.Join(repoDir, filepath.FromSlash(rel)))
	if err != nil {
		return "", err
	}
	text := string(raw)
	crlf := strings.Contains(text, "\r\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	sort.Slice(edits, func(i, j int) bool { return edits[i].line < edits[j].line })
	for i := range edits {
		e := &edits[i]
		if e.line < 1 || e.line > len(lines) {
			return "", fmt.Errorf("line %d is outside the file (%d lines)", e.line, len(lines))
		}
		orig := strings.TrimRight(lines[e.line-1], "\r")
		indent := orig[:len(orig)-len(strings.TrimLeft(orig, " \t"))]
		out := make([]string, len(e.repl))
		for k, r := range e.repl {
			out[k] = indent + r
			if crlf {
				out[k] += "\r"
			}
		}
		e.repl = out
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", rel, rel)
	for _, h := range hunks(len(lines), edits) {
		b.WriteString(renderHunk(lines, h))
	}
	return b.String(), nil
}

type hunk struct {
	lo, hi int // 1-based inclusive range of original lines
	edits  []lineEdit
}

func hunks(n int, edits []lineEdit) []hunk {
	var out []hunk
	for _, e := range edits {
		lo, hi := max(1, e.line-diffContext), min(n, e.line+diffContext)
		if k := len(out) - 1; k >= 0 && lo <= out[k].hi+1 {
			out[k].hi = hi
			out[k].edits = append(out[k].edits, e)
			continue
		}
		out = append(out, hunk{lo: lo, hi: hi, edits: []lineEdit{e}})
	}
	return out
}

func renderHunk(lines []string, h hunk) string {
	repl := map[int][]string{}
	added := 0
	for _, e := range h.edits {
		repl[e.line] = e.repl
		added += len(e.repl)
	}
	oldN := h.hi - h.lo + 1
	newN := oldN - len(h.edits) + added
	var b strings.Builder
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", h.lo, oldN, h.lo, newN)
	for i := h.lo; i <= h.hi; i++ {
		r, edited := repl[i]
		if !edited {
			b.WriteString(" " + lines[i-1] + "\n")
			continue
		}
		b.WriteString("-" + lines[i-1] + "\n")
		for _, l := range r {
			b.WriteString("+" + l + "\n")
		}
	}
	return b.String()
}

func newFileDiff(path, content string) string {
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	var b strings.Builder
	fmt.Fprintf(&b, "--- /dev/null\n+++ b/%s\n@@ -0,0 +1,%d @@\n", path, len(lines))
	for _, l := range lines {
		b.WriteString("+" + l + "\n")
	}
	return b.String()
}
