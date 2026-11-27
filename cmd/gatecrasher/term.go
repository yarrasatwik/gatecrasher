package main

import (
	"os"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// color is on when stdout is a terminal and NO_COLOR is unset.
var color = func() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func sgr(code, s string) string {
	if !color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string    { return sgr("1", s) }
func dim(s string) string     { return sgr("2", s) }
func red(s string) string     { return sgr("31", s) }
func green(s string) string   { return sgr("32", s) }
func yellow(s string) string  { return sgr("33", s) }
func cyan(s string) string    { return sgr("36", s) }
func bgRed(s string) string   { return sgr("1;37;41", s) }
func bgGreen(s string) string { return sgr("1;30;42", s) }

// safe redacts text before it reaches the terminal.
func safe(s string) string { return redact.String(s) }

func sevTag(s model.Severity) string {
	label := map[model.Severity]string{model.SevCritical: "CRIT", model.SevHigh: "HIGH", model.SevMedium: "MED ", model.SevLow: "LOW ", model.SevInfo: "INFO"}[s]
	switch s {
	case model.SevCritical:
		return sgr("1;37;45", " "+label+" ")
	case model.SevHigh:
		return sgr("1;37;41", " "+label+" ")
	case model.SevMedium:
		return sgr("1;30;43", " "+label+" ")
	default:
		return sgr("7", " "+label+" ")
	}
}

func envTag(env string, prod bool) string {
	if prod {
		return sgr("1;37;41", " "+env+" ")
	}
	return sgr("7", " "+env+" ")
}
