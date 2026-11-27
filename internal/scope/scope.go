// Package scope enforces Gatecrasher's scope lock: every outbound request
// must target a host that the operator explicitly allowed. There is no way to
// disable the lock (spec §3.3 rule 1).
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

// ErrOutOfScope is returned (wrapped) for any request outside the lock.
var ErrOutOfScope = errors.New("out of scope")

// Lock is an immutable allow-list of hosts. The zero value allows nothing.
type Lock struct {
	domains  map[string]struct{} // bare hostnames, any port; "*.x" suffix rules kept separately
	suffixes []string            // ".example.com" from "*.example.com"
	hostPort map[string]struct{} // exact host:port pairs
}

// New builds a lock from allowed domains (hostnames, optionally "*.suffix")
// and allowed API hosts ("host" or "host:port"). Empty entries are ignored.
func New(domains []string, apiHosts []string) (*Lock, error) {
	l := &Lock{domains: map[string]struct{}{}, hostPort: map[string]struct{}{}}
	add := func(raw string) error {
		h := strings.ToLower(strings.TrimSpace(raw))
		if h == "" {
			return nil
		}
		if strings.Contains(h, "://") {
			u, err := url.Parse(h)
			if err != nil || u.Host == "" {
				return fmt.Errorf("invalid scope entry %q", raw)
			}
			h = strings.ToLower(u.Host)
		}
		if h == "*" || h == "*." {
			return fmt.Errorf("wildcard-everything scope entry %q is not allowed", raw)
		}
		if strings.HasPrefix(h, "*.") {
			l.suffixes = append(l.suffixes, h[1:])
			return nil
		}
		if host, port, err := net.SplitHostPort(h); err == nil && port != "" {
			l.hostPort[host+":"+port] = struct{}{}
			return nil
		}
		l.domains[strings.Trim(h, "[]")] = struct{}{}
		return nil
	}
	for _, d := range domains {
		if err := add(d); err != nil {
			return nil, err
		}
	}
	for _, d := range apiHosts {
		if err := add(d); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// MustNew is New that panics; for constants and tests.
func MustNew(domains []string, apiHosts []string) *Lock {
	l, err := New(domains, apiHosts)
	if err != nil {
		panic(err)
	}
	return l
}

// CheckURL returns nil if raw is an http(s) URL whose host is in scope.
func (l *Lock) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: unparseable URL", ErrOutOfScope)
	}
	return l.Check(u)
}

// Check returns nil if u is an http(s) URL whose host is in scope.
func (l *Lock) Check(u *url.URL) error {
	if l == nil {
		return fmt.Errorf("%w: no scope configured", ErrOutOfScope)
	}
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%w: only http(s) URLs are allowed", ErrOutOfScope)
	}
	if u.User != nil {
		return fmt.Errorf("%w: URLs with credentials are refused", ErrOutOfScope)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrOutOfScope)
	}
	if _, ok := l.domains[host]; ok {
		return nil
	}
	if _, ok := l.hostPort[host+":"+port]; ok {
		return nil
	}
	for _, s := range l.suffixes {
		if strings.HasSuffix(host, s) && len(host) > len(s) {
			return nil
		}
	}
	return fmt.Errorf("%w: host %q is not in allowed_domains or allowed_api_hosts (edit gatecrasher.yaml)", ErrOutOfScope, u.Host)
}

// Entries returns the sorted allow-list for display in reports.
func (l *Lock) Entries() []string {
	if l == nil {
		return nil
	}
	out := make([]string, 0, len(l.domains)+len(l.hostPort)+len(l.suffixes))
	for d := range l.domains {
		out = append(out, d)
	}
	for d := range l.hostPort {
		out = append(out, d)
	}
	for _, s := range l.suffixes {
		out = append(out, "*"+s)
	}
	sort.Strings(out)
	return out
}
