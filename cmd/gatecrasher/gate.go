package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// agentEnvVars mark a session driven by a coding agent or a CI runner.
// Any of them set to a non-empty value means no person is at the keyboard.
var agentEnvVars = []string{"CI", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CURSOR_TRACE_ID", "GITHUB_ACTIONS", "GATECRASHER_AGENT"}

// humanChannels is where a person can approve a protected environment.
const humanChannels = "Approve it in the web UI (gatecrasher serve) or run this command yourself in a real terminal."

// gate decides whether this process may approve a change to a protected
// environment. Only a person at a real terminal may: stdin and stdout must
// both be terminals and the session must not belong to an agent or CI.
// The checks are fields so tests can simulate any session.
type gate struct {
	getenv    func(string) string
	stdinTTY  func() bool
	stdoutTTY func() bool
	in        *bufio.Reader
	out       io.Writer
}

// newGate builds the gate for the running process; tests replace it.
var newGate = systemGate

func systemGate() *gate {
	return &gate{
		getenv:    os.Getenv,
		stdinTTY:  func() bool { return isTerminal(os.Stdin) },
		stdoutTTY: func() bool { return isTerminal(os.Stdout) },
		in:        bufio.NewReader(os.Stdin),
		out:       os.Stdout,
	}
}

// isTerminal reports whether f is a character device (a console or tty),
// which pipes, files and sockets are not.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// gateError is a refusal to approve a protected environment from here.
type gateError struct{ msg string }

func (e *gateError) Error() string { return e.msg }

// agentSession returns the variable that marks an agent or CI session.
func (g *gate) agentSession() string {
	for _, k := range agentEnvVars {
		if g.getenv(k) != "" {
			return k
		}
	}
	return ""
}

// channel names how an approval from this process is recorded: "tty" when
// a person is at a real terminal, otherwise "cli".
func (g *gate) channel() string {
	if g.agentSession() == "" && g.stdinTTY() && g.stdoutTTY() {
		return "tty"
	}
	return "cli"
}

// refusal returns why this process may not approve a change to the
// protected environment env, or nil when a person is at a real terminal.
// confirmFlag says --confirm was passed, which a script can do as easily
// as a person.
func (g *gate) refusal(env string, confirmFlag bool) error {
	prefix := fmt.Sprintf("refusing to approve a change to the protected environment %q: ", env)
	if confirmFlag {
		return &gateError{prefix + "--confirm is not accepted here, because a flag can be passed by a script or a coding agent. " +
			humanChannels + " There you type the environment name and the last 4 characters of the plan hash."}
	}
	if k := g.agentSession(); k != "" {
		return &gateError{prefix + "this is a coding-agent or CI session (" + k + " is set), and an agent cannot approve. " + humanChannels}
	}
	var missing []string
	if !g.stdinTTY() {
		missing = append(missing, "stdin is not a terminal")
	}
	if !g.stdoutTTY() {
		missing = append(missing, "stdout is not a terminal")
	}
	if len(missing) > 0 {
		return &gateError{prefix + strings.Join(missing, " and ") + ", so the confirmation cannot come from a person. " + humanChannels}
	}
	return nil
}

// errSkipped means the person pressed Enter instead of confirming.
var errSkipped = errors.New("nothing typed; the plan was not approved")

// confirm asks the person to type the environment name and then the last
// 4 characters of the plan hash printed on screen. It returns the typed
// environment name. Callers must have checked refusal first.
func (g *gate) confirm(p model.Plan) (string, error) {
	if len(p.Hash) < 4 {
		return "", fmt.Errorf("plan %s has no hash to confirm against; re-plan", p.ID)
	}
	fmt.Fprintf(g.out, "    %s is a protected environment. Plan hash: %s\n", p.Environment, p.Hash)
	fmt.Fprintf(g.out, "    type the environment name to approve, or press Enter to skip: ")
	typed, err := g.readLine()
	if err != nil {
		return "", err
	}
	if typed == "" {
		return "", errSkipped
	}
	if typed != p.Environment {
		return "", fmt.Errorf("that is not the environment name (expected %q, got %q); the plan was not approved", p.Environment, typed)
	}
	fmt.Fprintf(g.out, "    type the last 4 characters of the plan hash shown above: ")
	suffix, err := g.readLine()
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(suffix, p.Hash[len(p.Hash)-4:]) {
		return "", errors.New("that is not the last 4 characters of the plan hash; the plan was not approved")
	}
	return typed, nil
}

// readLine reads one typed line. Input that ends before Enter was pressed
// is not a confirmation.
func (g *gate) readLine() (string, error) {
	line, err := g.in.ReadString('\n')
	if err != nil {
		return "", errors.New("input ended before the confirmation was typed; the plan was not approved")
	}
	return strings.TrimSpace(line), nil
}
