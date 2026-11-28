package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// writeDrafts prints each PR-draft step of a plan: the drafted text, then
// the verified diff (coloured +/-) or the note saying why there is none.
// Gatecrasher only prints it; it never applies or pushes code.
func writeDrafts(w io.Writer, p model.Plan) {
	for _, op := range p.Operations {
		if op.Kind != "pr.draft" || (op.Draft == "" && op.Diff == "" && op.DiffNote == "") {
			continue
		}
		fmt.Fprintf(w, "    %s %s\n", bold("PR draft"), dim("(guidance only: Gatecrasher never applies or pushes code)"))
		for _, l := range strings.Split(strings.TrimRight(safe(op.Draft), "\n"), "\n") {
			if op.Draft != "" {
				fmt.Fprintf(w, "      %s\n", l)
			}
		}
		if op.Diff != "" {
			fmt.Fprintf(w, "    %s\n", dim("proposed diff:"))
			for _, l := range strings.Split(strings.TrimRight(safe(op.Diff), "\n"), "\n") {
				fmt.Fprintf(w, "      %s\n", colourDiffLine(l))
			}
		}
		if op.DiffNote != "" {
			fmt.Fprintf(w, "    %s\n", dim(safe(op.DiffNote)))
		}
	}
}

func colourDiffLine(l string) string {
	switch {
	case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
		return bold(l)
	case strings.HasPrefix(l, "@@"):
		return cyan(l)
	case strings.HasPrefix(l, "+"):
		return green(l)
	case strings.HasPrefix(l, "-"):
		return red(l)
	}
	return l
}
