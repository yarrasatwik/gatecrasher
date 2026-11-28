package fixes

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/patch"
)

// serverFileNames are the files that usually serve the app and are where a
// server-side fix (a trait endpoint, a server-assigned identifier) goes.
var serverFileNames = []string{
	"main.go", "server.go", "server.js", "server.ts", "server.mjs", "app.py", "server.py", "main.py", "index.js",
}

// serverDirs are the app-repo directories searched for a server file, in order.
var serverDirs = []string{"", "server", "src", "backend", "cmd/server"}

// identifierCodeRe finds client code that picks or sends a Flagsmith
// identifier, for findings that have no scanned usage to point at.
var identifierCodeRe = regexp.MustCompile(`(?i)identif(?:y|ier)|visitor|flagsmith`)

// CollectSources returns the files the PR drafter may read and edit: the
// files named by the impact items (or, with no impact, client code that
// handles identifiers), plus the related server file when the repo has one.
// At most patch.MaxFiles are returned, each at most patch.MaxFileLines lines
// and patch.MaxFileBytes bytes (larger files are skipped, never truncated).
// Paths are repo-relative with forward slashes; only regular files inside
// repoDir are read, never hidden files such as .env, and the content is
// unredacted (the AI client redacts it before sending).
func CollectSources(repoDir string, impact []model.ImpactItem) []model.SourceFile {
	if repoDir == "" {
		return nil
	}
	root, err := filepath.EvalSymlinks(repoDir)
	if err != nil {
		return nil
	}
	var wanted []string
	seen := map[string]bool{}
	add := func(rel string) {
		if !seen[rel] {
			seen[rel] = true
			wanted = append(wanted, rel)
		}
	}
	for _, it := range impact {
		add(filepath.ToSlash(filepath.Clean(filepath.FromSlash(it.File))))
	}
	if len(impact) == 0 {
		for _, rel := range identifierFiles(root) {
			add(rel)
		}
	}
	var server *model.SourceFile
	for _, dir := range serverDirs {
		for _, name := range serverFileNames {
			rel := name
			if dir != "" {
				rel = dir + "/" + name
			}
			if seen[rel] {
				continue
			}
			if sf, ok := readSource(root, rel); ok {
				server = &sf
				break
			}
		}
		if server != nil {
			break
		}
	}
	limit := patch.MaxFiles
	if server != nil {
		limit--
	}
	var out []model.SourceFile
	for _, rel := range wanted {
		if len(out) == limit {
			break
		}
		if sf, ok := readSource(root, rel); ok {
			out = append(out, sf)
		}
	}
	if server != nil {
		out = append(out, *server)
	}
	return out
}

// readSource reads one eligible, bounded, regular text file inside root.
func readSource(root, rel string) (model.SourceFile, bool) {
	if !patch.Eligible(rel) {
		return model.SourceFile{}, false
	}
	full, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return model.SourceFile{}, false
	}
	if inside, err := filepath.Rel(root, full); err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return model.SourceFile{}, false
	}
	info, err := os.Stat(full)
	if err != nil || !info.Mode().IsRegular() || info.Size() > patch.MaxFileBytes {
		return model.SourceFile{}, false
	}
	raw, err := os.ReadFile(full)
	if err != nil || !utf8.Valid(raw) || strings.IndexByte(string(raw), 0) >= 0 {
		return model.SourceFile{}, false
	}
	text := string(raw)
	if !patch.WithinLimits(text) {
		return model.SourceFile{}, false
	}
	return model.SourceFile{Path: rel, Content: text}, true
}

// identifierFiles lists client-code files that mention identifiers or the
// Flagsmith client, sorted by path.
func identifierFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !scanExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if sf, ok := readSource(root, rel); ok && identifierCodeRe.MatchString(sf.Content) {
			out = append(out, rel)
		}
		return nil
	})
	return out
}
