package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

const testWriteKey = "writekey.abcdefghijklmnopqrstuvwxyz012345"

// Only serve and the interactive write paths may load the write key.
// This walks the command sources and fails if any other command (MCP,
// audit, ci, watch, plan, report, parity, ...) reaches for it.
func TestOnlyServeAndInteractiveWritesLoadTheWriteKey(t *testing.T) {
	allowed := map[string]bool{"cmdServe": true, "cmdApply": true, "cmdRollback": true, "fixAll": true, "loadWriter": true}
	fset := token.NewFileSet()
	callers := map[string][]string{} // function -> loaders it calls
	for _, file := range []string{"commands.go", "serve.go", "mcp.go", "main.go", "lab.go", "gate.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "loadForWrites" || id.Name == "loadWriter") {
						callers[fn.Name.Name] = append(callers[fn.Name.Name], id.Name)
					}
				}
				return true
			})
		}
	}
	var got []string
	for fn := range callers {
		got = append(got, fn)
		if !allowed[fn] {
			t.Errorf("%s loads the write key; only serve and the interactive apply/rollback/fix-all paths may", fn)
		}
	}
	sort.Strings(got)
	for _, want := range []string{"cmdServe", "cmdApply", "cmdRollback", "fixAll"} {
		if len(callers[want]) == 0 {
			t.Errorf("%s no longer loads the write key (have %s)", want, strings.Join(got, ", "))
		}
	}
}

func TestWriteKeyIsLoadedOnlyForAPersonAtATerminal(t *testing.T) {
	cfgPath, _ := workspace(t)
	t.Setenv("GATECRASHER_WRITE_API_KEY", testWriteKey)
	c := &common{config: cfgPath}

	a, err := load(c)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cfg.WriteAPIKey != "" {
		t.Fatal("load (audit, ci, mcp, watch, plan, report, parity) read the write key")
	}

	person, _ := fakeGate(nil, true, true, "")
	if a, err = loadWriter(c, person); err != nil || a.Cfg.WriteAPIKey != testWriteKey {
		t.Fatalf("a person at a terminal must get the write key (err %v)", err)
	}
	for name, g := range map[string]*gate{
		"agent session": mustGate(map[string]string{"CLAUDECODE": "1"}, true, true),
		"CI":            mustGate(map[string]string{"CI": "true"}, true, true),
		"piped stdin":   mustGate(nil, false, true),
		"piped stdout":  mustGate(nil, true, false),
	} {
		a, err := loadWriter(c, g)
		if err != nil {
			t.Fatal(err)
		}
		if a.Cfg.WriteAPIKey != "" {
			t.Errorf("%s: the write key was loaded outside a real terminal", name)
		}
	}
}

func TestServeNotesWhenKeysAreNotSplit(t *testing.T) {
	cfgPath, _ := workspace(t)
	t.Setenv("GATECRASHER_ORG_API_KEY", "orgkey01.abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("GATECRASHER_WRITE_API_KEY", "")
	a, err := loadForWrites(&common{config: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if note := keySplitNote(a); !strings.Contains(note, "keys are not split") {
		t.Fatalf("note = %q", note)
	}
	t.Setenv("GATECRASHER_WRITE_API_KEY", testWriteKey)
	a, err = loadForWrites(&common{config: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if note := keySplitNote(a); note != "" {
		t.Fatalf("split keys must print no note, got %q", note)
	}
}

func mustGate(env map[string]string, stdinTTY, stdoutTTY bool) *gate {
	g, _ := fakeGate(env, stdinTTY, stdoutTTY, "")
	return g
}
