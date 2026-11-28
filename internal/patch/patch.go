// Package patch checks that a unified diff produced by the AI can be applied
// to a known set of files, without ever writing anything. It is a small
// in-memory equivalent of `git apply --check`: hunks are located by their
// context (so a slightly wrong line number is tolerated, as with git's
// offset), and the diff is re-emitted with correct hunk headers so what is
// stored and shown is a canonical diff that `git apply` accepts.
package patch

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

var (
	// ErrOutsideFiles means the diff touches a path that was not provided
	// (or creates, deletes or renames one).
	ErrOutsideFiles = errors.New("diff touches a file that was not provided")
	// ErrNotApplicable means the diff is malformed or its context does not
	// match the provided file contents.
	ErrNotApplicable = errors.New("diff does not apply")
)

// Result is a verified diff.
type Result struct {
	// Diff is the canonical unified diff (headers recomputed).
	Diff string
	// New holds the patched content of every touched file.
	New map[string]string
}

var hunkRe = regexp.MustCompile(`^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@`)

type hunkLine struct {
	kind byte // ' ', '-', '+'
	text string
}

type hunk struct {
	oldStart int
	lines    []hunkLine
}

type filePatch struct {
	path  string
	hunks []hunk
}

// Apply verifies diff against files and returns the canonical diff and the
// patched contents. Nothing is written anywhere.
func Apply(files []model.SourceFile, diff string) (*Result, error) {
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = f.Content
	}
	patches, err := parse(diff, byPath)
	if err != nil {
		return nil, err
	}
	res := &Result{New: map[string]string{}}
	var out strings.Builder
	for _, fp := range patches {
		text, body, err := applyFile(byPath[fp.path], fp)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrNotApplicable, fp.path, err)
		}
		res.New[fp.path] = text
		fmt.Fprintf(&out, "--- a/%s\n+++ b/%s\n%s", fp.path, fp.path, body)
	}
	res.Diff = out.String()
	return res, nil
}

func cleanPath(p string) string {
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"`)
	if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
		p = p[2:]
	}
	return p
}

func parse(diff string, allowed map[string]string) ([]filePatch, error) {
	diff = strings.TrimSpace(strings.ReplaceAll(diff, "\r\n", "\n"))
	if diff == "" {
		return nil, fmt.Errorf("%w: empty diff", ErrNotApplicable)
	}
	lines := strings.Split(diff, "\n")
	var out []filePatch
	seen := map[string]bool{}
	for i := 0; i < len(lines); {
		l := lines[i]
		switch {
		case strings.HasPrefix(l, "new file mode"), strings.HasPrefix(l, "deleted file mode"),
			strings.HasPrefix(l, "rename "), strings.HasPrefix(l, "copy "),
			strings.HasPrefix(l, "Binary files"), strings.HasPrefix(l, "GIT binary patch"):
			return nil, fmt.Errorf("%w: only in-place edits of provided files are allowed", ErrOutsideFiles)
		case strings.HasPrefix(l, "--- ") && i+1 < len(lines) && strings.HasPrefix(lines[i+1], "+++ "):
			oldP, newP := cleanPath(l[4:]), cleanPath(lines[i+1][4:])
			if oldP == "/dev/null" || newP == "/dev/null" || oldP != newP {
				return nil, fmt.Errorf("%w: only in-place edits of provided files are allowed", ErrOutsideFiles)
			}
			if _, ok := allowed[oldP]; !ok || strings.Contains(oldP, "..") {
				return nil, fmt.Errorf("%w: %q", ErrOutsideFiles, oldP)
			}
			if seen[oldP] {
				return nil, fmt.Errorf("%w: %s appears twice", ErrNotApplicable, oldP)
			}
			seen[oldP] = true
			fp := filePatch{path: oldP}
			i += 2
			for i < len(lines) && strings.HasPrefix(lines[i], "@@") {
				m := hunkRe.FindStringSubmatch(lines[i])
				if m == nil {
					return nil, fmt.Errorf("%w: bad hunk header %q", ErrNotApplicable, lines[i])
				}
				start, _ := strconv.Atoi(m[1])
				h := hunk{oldStart: start}
				i++
				for i < len(lines) && !strings.HasPrefix(lines[i], "@@") &&
					!(strings.HasPrefix(lines[i], "--- ") && i+1 < len(lines) && strings.HasPrefix(lines[i+1], "+++ ")) &&
					!strings.HasPrefix(lines[i], "diff --git") {
					t := lines[i]
					switch {
					case t == "":
						h.lines = append(h.lines, hunkLine{' ', ""})
					case t[0] == ' ' || t[0] == '-' || t[0] == '+':
						h.lines = append(h.lines, hunkLine{t[0], t[1:]})
					case t[0] == '\\':
						// "\ No newline at end of file": handled by applyFile's EOF rule.
					default:
						return nil, fmt.Errorf("%w: unexpected line %q in hunk", ErrNotApplicable, t)
					}
					i++
				}
				fp.hunks = append(fp.hunks, h)
			}
			if len(fp.hunks) == 0 {
				return nil, fmt.Errorf("%w: %s has no hunks", ErrNotApplicable, oldP)
			}
			out = append(out, fp)
		default:
			i++ // diff --git, index, mode lines, prose before the header
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no file headers found", ErrNotApplicable)
	}
	return out, nil
}

func eq(a, b string) bool { return strings.TrimSuffix(a, "\r") == strings.TrimSuffix(b, "\r") }

func applyFile(content string, fp filePatch) (newText, body string, err error) {
	endsNL := strings.HasSuffix(content, "\n")
	crlf := strings.Contains(content, "\r\n")
	src := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if content == "" {
		src = nil
	}
	var res []string
	var b strings.Builder
	cur, delta := 0, 0 // next unconsumed source line, new-minus-old line offset
	for n, h := range fp.hunks {
		var old, add []string
		trail := 0
		changed := false
		for _, hl := range h.lines {
			switch hl.kind {
			case ' ':
				old, add = append(old, hl.text), append(add, hl.text)
				if changed {
					trail++
				}
			case '-':
				old, changed, trail = append(old, hl.text), true, 0
			case '+':
				add, changed, trail = append(add, hl.text), true, 0
			}
		}
		if !changed {
			return "", "", fmt.Errorf("hunk %d changes nothing", n+1)
		}
		if len(old) == 0 {
			return "", "", fmt.Errorf("hunk %d has no context lines", n+1)
		}
		want := h.oldStart - 1
		best := -1
		for p := cur; p+len(old) <= len(src); p++ {
			ok := true
			for k, o := range old {
				if !eq(src[p+k], o) {
					ok = false
					break
				}
			}
			if !ok || (trail == 0 && p+len(old) != len(src)) {
				continue
			}
			if best < 0 || abs(p-want) < abs(best-want) {
				best = p
			}
		}
		if best < 0 {
			return "", "", fmt.Errorf("hunk %d context does not match the file", n+1)
		}
		if !endsNL && best+len(old) == len(src) {
			return "", "", fmt.Errorf("hunk %d reaches a last line without a newline", n+1)
		}
		res = append(res, src[cur:best]...)
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", best+1, len(old), best+1+delta, len(add))
		pos := best
		for _, hl := range h.lines {
			switch hl.kind {
			case ' ': // the file's own line, so line endings are exact
				b.WriteString(" " + src[pos] + "\n")
				res = append(res, src[pos])
				pos++
			case '-':
				b.WriteString("-" + src[pos] + "\n")
				pos++
			case '+':
				line := strings.TrimSuffix(hl.text, "\r")
				if crlf {
					line += "\r"
				}
				b.WriteString("+" + line + "\n")
				res = append(res, line)
			}
		}
		delta += len(add) - len(old)
		cur = best + len(old)
	}
	res = append(res, src[cur:]...)
	newText = strings.Join(res, "\n")
	if endsNL && len(res) > 0 {
		newText += "\n"
	}
	return newText, b.String(), nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
