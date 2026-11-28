package patch

import "strings"

// Limits on what the PR drafter is given.
const (
	MaxFiles     = 4
	MaxFileLines = 400
	MaxFileBytes = 24 * 1024
)

// Eligible reports whether a repo-relative path may be sent to the drafter
// and edited by its diff: clean, relative, not hidden (.env, .git, ...) and
// not obvious key material.
func Eligible(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, `\`) || strings.Contains(path, "..") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || strings.HasPrefix(part, ".") {
			return false
		}
	}
	base := strings.ToLower(path[strings.LastIndexByte(path, '/')+1:])
	switch {
	case strings.HasSuffix(base, ".pem"), strings.HasSuffix(base, ".key"), strings.HasSuffix(base, ".p12"),
		strings.HasPrefix(base, "id_rsa"), strings.HasPrefix(base, "id_ed25519"),
		strings.Contains(base, "credentials"), strings.Contains(base, "secrets"):
		return false
	}
	return true
}

// WithinLimits reports whether a file is small enough to send whole.
func WithinLimits(content string) bool {
	return len(content) <= MaxFileBytes && strings.Count(content, "\n") <= MaxFileLines
}
