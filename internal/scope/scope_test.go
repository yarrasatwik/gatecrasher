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

// host:port entries work in allowed_domains as well as allowed_api_hosts and
// match that port only; a bare host matches every port.
func TestHostPortEntriesPinThePort(t *testing.T) {
	pinned := MustNew([]string{"localhost:3030", "http://shop.test:8080/path", "[::1]:3030"}, []string{"localhost:8000"})
	for url, ok := range map[string]bool{
		"http://localhost:3030/":         true,
		"http://LOCALHOST:3030/app.js":   true,
		"http://localhost:8000/api/v1/":  true,
		"http://shop.test:8080/":         true,
		"http://[::1]:3030/":             true,
		"http://localhost/":              false,
		"https://localhost/":             false,
		"http://localhost:22/":           false,
		"http://localhost:30300/":        false,
		"http://localhost:8787/":         false,
		"http://shop.test/":              false,
		"http://[::1]:8000/":             false,
		"http://localhost:3030@evil.io/": false,
	} {
		if err := pinned.CheckURL(url); (err == nil) != ok {
			t.Errorf("pinned %s: err=%v, want ok=%v", url, err, ok)
		}
	}
	// Default ports are matched when the entry names them.
	web := MustNew([]string{"shop.test:443"}, nil)
	if web.CheckURL("https://shop.test/") != nil || web.CheckURL("http://shop.test/") == nil {
		t.Error("shop.test:443 must allow https on the default port only")
	}
	if got := pinned.Entries(); len(got) != 4 {
		t.Errorf("entries = %v", got)
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
