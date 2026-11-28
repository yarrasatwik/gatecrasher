package main

import (
	"errors"
	"os"
	"testing"
)

func TestColorEnabled(t *testing.T) {
	pipe := func() (os.FileInfo, error) { return nil, errors.New("pipe") }
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if colorEnabled(env(nil), pipe) {
		t.Error("a pipe must not get colour")
	}
	if !colorEnabled(env(map[string]string{"CLICOLOR_FORCE": "1"}), pipe) {
		t.Error("CLICOLOR_FORCE must force colour")
	}
	if colorEnabled(env(map[string]string{"CLICOLOR_FORCE": "1", "NO_COLOR": "1"}), pipe) {
		t.Error("NO_COLOR wins")
	}
}
