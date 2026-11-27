package fixes

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// UsageKind says what a client-side Flagsmith call does.
type UsageKind string

// Usage kinds.
const (
	// UsageTraitWrite is a client-side write of one or more traits.
	UsageTraitWrite UsageKind = "trait-write"
	// UsageFlagRead is a client-side read of one or more flags.
	UsageFlagRead UsageKind = "flag-read"
)

// Usage is one client-side Flagsmith call found in the app repo.
type Usage struct {
	Kind UsageKind
	// Names are the trait or flag names the call mentions; empty when the
	// call passes a non-literal name.
	Names   []string
	File    string // repo-relative, forward slashes
	Line    int
	Snippet string // trimmed and redacted
}

const (
	maxScanFileBytes = 1 << 20
	maxScanLineBytes = 4000
	maxSnippetChars  = 160
)

var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, "dist": true, "build": true,
}

var scanExts = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true,
	".swift": true, ".kt": true, ".kts": true, ".dart": true, ".html": true, ".htm": true,
}

// serverSDKMarker identifies JS/TS files that use the Flagsmith *server*
// SDK; their flag reads are not client-side.
var serverSDKMarker = regexp.MustCompile(`flagsmith-nodejs|flagsmith-java|flagsmith-go|flagsmith-python`)

const quoted = `["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`

var (
	// setTrait("k", v), updateTrait("k", v).
	singleTraitRe = regexp.MustCompile(`\b(?:setTrait|updateTrait)\s*\(\s*(?:\w+\s*[:=]\s*)?` + quoted)
	// Swift/Kotlin/Dart Trait(key: "k") / Trait(key = "k").
	traitKeyRe = regexp.MustCompile(`\bTrait\s*\(\s*key\s*[:=]\s*` + quoted)
	// setTraits({a: 1, b: 2}) and identify(..., {traits: {a: 1}}) / init({traits: {...}}).
	objTraitsRe = regexp.MustCompile(`\bsetTraits\s*\(\s*\{([^}]*)\}?|\btraits\s*:\s*\{([^}]*)\}?`)
	// Calls that take traits but pass a non-literal (still client-side writes).
	opaqueTraitsRe = regexp.MustCompile(`\b(?:setTraits|updateTraits)\s*\(`)
	objKeyRe       = regexp.MustCompile(`(?:^|[,{\s])["']?([A-Za-z_][\w.\-]*)["']?\s*:`)

	flagReadRe = regexp.MustCompile(`\b(?:getValue|hasFeature|getFeatureValue|getFeatureEnabled|isFeatureEnabled|` +
		`getFlag|getFlagValue|hasFeatureFlag|getValueSafe|getBooleanValue|getStringValue|getIntValue|` +
		`getNumberValue|getJsonValue|featureEnabled)\s*\(\s*(?:\w+\s*[:=]\s*)?` + quoted)
	useFlagsRe = regexp.MustCompile(`\buseFlags\s*\(\s*\[([^\]]*)\]`)
	quotedRe   = regexp.MustCompile(quoted)
)

// ScanUsages walks dir for client-side Flagsmith usage in JS/TS/JSX/TSX,
// Swift, Kotlin, Dart and HTML (inline scripts). It skips node_modules,
// vendor, .git, dist, build and files over 1 MB.
func ScanUsages(dir string) ([]Usage, error) {
	var out []Usage
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !scanExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if info, ierr := d.Info(); ierr != nil || info.Size() > maxScanFileBytes {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		found, ferr := scanFile(path, filepath.ToSlash(rel))
		if ferr != nil {
			return ferr
		}
		out = append(out, found...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", dir, err)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}

// Scan is ScanUsages expressed as model.ImpactItems. Breaks is false: the
// planner decides what a particular fix breaks.
func Scan(dir string) ([]model.ImpactItem, error) {
	us, err := ScanUsages(dir)
	if err != nil {
		return nil, err
	}
	items := make([]model.ImpactItem, 0, len(us))
	for _, u := range us {
		items = append(items, model.ImpactItem{File: u.File, Line: u.Line, Snippet: u.Snippet, Message: usageMessage(u)})
	}
	return items, nil
}

func usageMessage(u Usage) string {
	names := "(non-literal name)"
	if len(u.Names) > 0 {
		names = "`" + strings.Join(u.Names, "`, `") + "`"
	}
	if u.Kind == UsageTraitWrite {
		return "sets trait " + names + " client-side"
	}
	return "reads flag " + names + " in client code"
}

func scanFile(path, rel string) ([]Usage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var (
		lines  []string
		server bool
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxScanFileBytes)
	for sc.Scan() {
		t := sc.Text()
		if serverSDKMarker.MatchString(t) {
			server = true
		}
		lines = append(lines, t)
	}
	if err := sc.Err(); err != nil {
		return nil, nil // unreadable or pathological file: skip rather than fail the whole scan
	}
	if server {
		return nil, nil
	}
	var out []Usage
	for i, line := range lines {
		if len(line) > maxScanLineBytes {
			continue
		}
		for _, kind := range []UsageKind{UsageTraitWrite, UsageFlagRead} {
			if names, ok := matchLine(kind, line); ok {
				out = append(out, Usage{Kind: kind, Names: names, File: rel, Line: i + 1, Snippet: snippet(line)})
			}
		}
	}
	return out, nil
}

// matchLine reports whether the line contains a usage of kind, with the
// distinct names it mentions.
func matchLine(kind UsageKind, line string) ([]string, bool) {
	set := map[string]bool{}
	hit := false
	add := func(n string) {
		hit = true
		if n != "" {
			set[n] = true
		}
	}
	if kind == UsageFlagRead {
		for _, m := range flagReadRe.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
		for _, m := range useFlagsRe.FindAllStringSubmatch(line, -1) {
			for _, q := range quotedRe.FindAllStringSubmatch(m[1], -1) {
				add(q[1])
			}
		}
	} else {
		for _, re := range []*regexp.Regexp{singleTraitRe, traitKeyRe} {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				add(m[1])
			}
		}
		for _, m := range objTraitsRe.FindAllStringSubmatch(line, -1) {
			body := m[1] + m[2]
			hit = true
			for _, k := range objKeyRe.FindAllStringSubmatch(body, -1) {
				add(k[1])
			}
		}
		if !hit && opaqueTraitsRe.MatchString(line) {
			add("")
		}
	}
	if !hit {
		return nil, false
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, true
}

func snippet(line string) string {
	s := strings.TrimSpace(redact.String(line))
	if len(s) > maxSnippetChars {
		s = s[:maxSnippetChars] + "…"
	}
	return s
}
