package scope

import (
	"errors"
	"testing"
)

func TestCheck(t *testing.T) {
	l := MustNew([]string{"localhost", "*.acmeshop.dev"}, []string{"flags.example.com:8443", "https://api.flagsmith.com"})
	cases := []struct {
		url string
		ok  bool
	}{
		{"http://localhost:3030/", true},
		{"http://localhost/anything", true},
		{"https://shop.acmeshop.dev/app.js", true},
		{"https://acmeshop.dev/", false}, // suffix rule needs a subdomain
		{"https://evilacmeshop.dev/", false},
		{"https://flags.example.com:8443/api/v1/", true},
		{"https://flags.example.com/api/v1/", false}, // wrong port
		{"https://api.flagsmith.com/api/v1/flags/", true},
		{"https://example.org/", false},
		{"ftp://localhost/", false},
		{"http://user:pw@localhost/", false},
		{"http://127.0.0.1:3030/", false},
		{"not a url", false},
	}
	for _, c := range cases {
		err := l.CheckURL(c.url)
		if (err == nil) != c.ok {
			t.Errorf("%s: got err=%v, want ok=%v", c.url, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrOutOfScope) {
			t.Errorf("%s: error does not wrap ErrOutOfScope: %v", c.url, err)
		}
	}
}

func TestNilEmptyAndWildcardRefused(t *testing.T) {
	var l *Lock
	if l.CheckURL("http://localhost/") == nil {
		t.Fatal("nil lock must refuse")
	}
	if _, err := New([]string{"*"}, nil); err == nil {
		t.Fatal("wildcard-everything must be rejected")
	}
	if MustNew(nil, nil).CheckURL("http://localhost/") == nil {
		t.Fatal("empty lock must refuse")
	}
}

func TestEntriesSorted(t *testing.T) {
	got := MustNew([]string{"b.dev", "a.dev"}, []string{"c.dev:1"}).Entries()
	want := []string{"a.dev", "b.dev", "c.dev:1"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
