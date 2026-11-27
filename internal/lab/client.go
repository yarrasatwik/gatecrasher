package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

// api is a thin Flagsmith REST client scoped to the lab's own host.
type api struct {
	http *httpx.Client
	base string // API base with trailing slash, e.g. http://localhost:8000/api/v1/
}

// auth is the set of request headers that authenticate one call.
type auth map[string]string

func tokenAuth(token string) auth   { return auth{"Authorization": "Token " + token} }
func orgKeyAuth(key string) auth    { return auth{"Authorization": "Api-Key " + key} }
func clientKeyAuth(key string) auth { return auth{"X-Environment-Key": key} }

func newAPI(apiURL string) (*api, error) {
	u, err := url.Parse(apiURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid Flagsmith API URL %q", apiURL)
	}
	lock, err := scope.New(nil, []string{u.Host})
	if err != nil {
		return nil, err
	}
	base := apiURL
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return &api{http: httpx.New(lock, httpx.WithTimeout(30*time.Second)), base: base}, nil
}

// origin returns scheme://host of the API, used for the health check.
func (a *api) origin() string {
	u, _ := url.Parse(a.base)
	return u.Scheme + "://" + u.Host
}

// call performs one request and decodes a 2xx JSON response into out.
func (a *api) call(ctx context.Context, h auth, method, path string, body, out any) error {
	_, err := a.http.JSON(ctx, httpx.Request{Method: method, URL: a.resolve(path), Header: h, Body: body}, out)
	return err
}

// status performs one request and returns the HTTP status without failing on
// non-2xx responses.
func (a *api) status(ctx context.Context, h auth, method, path string, body any) (int, error) {
	resp, err := a.http.Do(ctx, httpx.Request{Method: method, URL: a.resolve(path), Header: h, Body: body})
	if err != nil {
		return 0, err
	}
	return resp.Status, nil
}

func (a *api) resolve(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return httpx.JoinURL(a.base, path)
}

// list fetches a list endpoint that is either a bare array or a paginated
// {results,next} object, following next links.
func list[T any](ctx context.Context, a *api, h auth, path string) ([]T, error) {
	var all []T
	next := path
	for page := 0; next != "" && page < 50; page++ {
		var raw json.RawMessage
		if err := a.call(ctx, h, "GET", next, nil, &raw); err != nil {
			return nil, err
		}
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
			var items []T
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, err
			}
			return append(all, items...), nil
		}
		var pg struct {
			Results []T     `json:"results"`
			Next    *string `json:"next"`
		}
		if err := json.Unmarshal(raw, &pg); err != nil {
			return nil, err
		}
		all = append(all, pg.Results...)
		next = ""
		if pg.Next != nil {
			next = *pg.Next
		}
	}
	return all, nil
}
