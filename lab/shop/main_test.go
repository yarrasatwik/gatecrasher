package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const fakeFlags = `[{"feature":{"name":"payment_config"},"feature_state_value":"{\"provider\":\"acmepay\",\"api_secret\":\"acme_live_0123456789abcdef0123456789abcdef\",\"webhook\":\"https://internal.acmeshop.dev/pay\"}"}]`

func testShop(t *testing.T, flags string, status int) *shop {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Environment-Key") != "ser.test" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(flags))
	}))
	t.Cleanup(api.Close)
	return &shop{apiURL: api.URL + "/", clientKey: "CLIENTKEY123", serverKey: "ser.test", http: api.Client()}
}

func TestCheckoutConfigReturnsOnlyNonSecretFields(t *testing.T) {
	s := testShop(t, fakeFlags, http.StatusOK)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/checkout-config", nil))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "acmepay") || !strings.Contains(body, "internal.acmeshop.dev") {
		t.Fatalf("status %d body %s", rec.Code, body)
	}
	if strings.Contains(body, "acme_live_") || strings.Contains(body, "api_secret") {
		t.Fatalf("secret leaked: %s", body)
	}
}

func TestCheckoutConfigReportsMissingFlag(t *testing.T) {
	s := testShop(t, `[]`, http.StatusOK)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/checkout-config", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestAppJSInjectsKeyWithoutShiftingLines(t *testing.T) {
	s := testShop(t, fakeFlags, http.StatusOK)
	raw, err := assets.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/app.js", nil))
	got := rec.Body.String()
	if !strings.Contains(got, `"CLIENTKEY123"`) || strings.Contains(got, "__FLAGSMITH_CLIENT_KEY__") {
		t.Fatal("client key was not injected")
	}
	if strings.Count(got, "\n") != strings.Count(string(raw), "\n") {
		t.Fatal("serving app.js must not change its line count")
	}
	for i, line := range strings.Split(got, "\n") {
		if strings.Contains(line, `setTrait("plan"`) {
			t.Logf("setTrait(\"plan\" is on app.js line %d", i+1)
			return
		}
	}
	t.Fatal(`app.js lost its setTrait("plan" line`)
}

func TestPair(t *testing.T) {
	if got := pair("Development=a,Production=b", "Production"); got != "b" {
		t.Fatalf("got %q", got)
	}
}
