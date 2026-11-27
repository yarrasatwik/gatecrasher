package report

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// format is one on-disk report rendering.
type format struct {
	ext   string
	write func(io.Writer, *model.Report) error
}

var formats = []format{
	{"json", WriteJSON},
	{"md", WriteMarkdown},
	{"html", WriteHTML},
	{"sarif", WriteSARIF},
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// WriteAll renders r as JSON, Markdown, HTML and SARIF into dir, writing
// latest.<ext> and <report-id>.<ext> for each. It returns every path written.
func WriteAll(dir string, r *model.Report) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create report dir: %w", err)
	}
	id := strings.TrimLeft(unsafeName.ReplaceAllString(r.ID, "_"), ".")
	if id == "" {
		id = "report"
	}
	var written []string
	for _, f := range formats {
		var buf bytes.Buffer
		if err := f.write(&buf, r); err != nil {
			return written, err
		}
		for _, name := range []string{"latest", id} {
			path := filepath.Join(dir, name+"."+f.ext)
			if err := writeFileAtomic(path, buf.Bytes()); err != nil {
				return written, err
			}
			written = append(written, path)
		}
	}
	return written, nil
}

// writeFileAtomic writes data to a temp file and renames it into place so a
// reader never sees a partial report.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".report-*")
	if err != nil {
		return fmt.Errorf("create temp report file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	return nil
}
