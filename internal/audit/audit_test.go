package audit

import (
	"os"
	"strings"
	"testing"
)

func newLog(t *testing.T, n int) *Log {
	t.Helper()
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := l.Append("tester", ActionPlan, "plan-0000000"+string(rune('a'+i)), map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func lines(t *testing.T, l *Log) []string {
	t.Helper()
	b, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func write(t *testing.T, l *Log, ls []string) {
	t.Helper()
	if err := os.WriteFile(l.Path(), []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChainValidAndLinked(t *testing.T) {
	l := newLog(t, 4)
	ok, at, err := l.Verify()
	if err != nil || !ok || at != 0 {
		t.Fatalf("Verify = %v %d %v", ok, at, err)
	}
	es, _ := l.Entries()
	if len(es) != 4 || es[0].PrevHash != "" || es[1].PrevHash != es[0].Hash || es[3].Seq != 4 {
		t.Fatalf("bad chain: %+v", es)
	}
	if seq, h, _ := l.Head(); seq != 4 || h != es[3].Hash {
		t.Fatalf("Head = %d %s", seq, h)
	}
}

func TestEmptyLogIsValid(t *testing.T) {
	l := newLog(t, 0)
	if ok, _, err := l.Verify(); !ok || err != nil {
		t.Fatalf("empty log: %v %v", ok, err)
	}
}

func TestTamperDetection(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(ls []string) []string
		at     int
	}{
		{"edit", func(ls []string) []string { ls[1] = strings.Replace(ls[1], `"tester"`, `"mallory"`, 1); return ls }, 2},
		{"delete middle", func(ls []string) []string { return append(ls[:1:1], ls[2:]...) }, 2},
		{"delete first", func(ls []string) []string { return ls[1:] }, 1},
		{"reorder", func(ls []string) []string { ls[1], ls[2] = ls[2], ls[1]; return ls }, 2},
		{"garbage line", func(ls []string) []string { ls[2] = "not json"; return ls }, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newLog(t, 4)
			write(t, l, tc.mutate(lines(t, l)))
			ok, at, err := l.Verify()
			if err != nil || ok || at != tc.at {
				t.Fatalf("Verify = %v %d %v, want broken at %d", ok, at, err, tc.at)
			}
		})
	}
}

func TestAppendRefusesCorruptLog(t *testing.T) {
	l := newLog(t, 3)
	ls := lines(t, l)
	ls[2] = "not json"
	write(t, l, ls)
	if _, err := l.Append("x", ActionPlan, "", nil); err == nil {
		t.Fatal("append to a corrupt log should fail")
	}
}

func TestDetailsRedactedAndActionValidated(t *testing.T) {
	l := newLog(t, 0)
	secret := "ser." + strings.Repeat("a1", 12)
	e, err := l.Append("me", ActionApply, "plan-12345678", map[string]any{"msg": "key is " + secret, "nested": []any{secret}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(l.Path())
	if strings.Contains(string(raw), secret) || strings.Contains(string(e.Details), secret) {
		t.Fatal("secret leaked into audit log")
	}
	if _, err := l.Append("me", Action("bogus"), "", nil); err == nil {
		t.Fatal("unknown action accepted")
	}
	if ok, _, _ := l.Verify(); !ok {
		t.Fatal("chain should still verify")
	}
}

func TestConcurrentAppends(t *testing.T) {
	l := newLog(t, 0)
	done := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() { _, err := l.Append("c", ActionVerify, "", nil); done <- err }()
	}
	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if ok, at, _ := l.Verify(); !ok {
		t.Fatalf("chain broken at %d", at)
	}
}
