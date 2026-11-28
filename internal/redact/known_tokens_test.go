package redact

import (
	"strings"
	"testing"
)

func TestKnownTokenFormatsRedacted(t *testing.T) {
	Reset()
	const hex = "9e107d9d372bb6826bd81d3542a419d6"
	for name, v := range map[string]string{
		"slack":    "https://hooks." + "slack.com/services/T0123ABCD/B0456EFGH/Xk3j9QpLm2Zr8TvNb4Wc7YdA",
		"discord":  "https://discord.com/api/" + "webhooks/1098765432109876543/aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3vW5x",
		"openai":   "s" + "k-proj-Xk3j9QpLm2Zr8TvNb4Wc7YdAeF5gH6iJ1kL2mN3oP4qR5sT",
		"sendgrid": "S" + "G.Xk3j9QpLm2Zr8TvNb4Wc7Y.dAeF5gH6iJ1kL2mN3oP4qR5sT6uV7wX8yZ9aB0cD1eF",
		"google":   "GOC" + "SPX-Xk3j9QpLm2Zr8TvNb4Wc7YdAeF5g",
		"npm":      "np" + "m_Xk3j9QpLm2Zr8TvNb4Wc7YdAeF5gH6iJ1kL2",
		"twilio":   "AC" + hex + " 0f1e2d3c4b5a69788796a5b4c3d2e1f0",
	} {
		out := String("value " + v + " end")
		if strings.Contains(out, v[len(v)-12:]) {
			t.Errorf("%s not redacted: %q", name, out)
		}
	}
	const benign = "see https://discord.com/invite/acmeshop and task-1234 skeleton-loader-animation-pulse"
	if got := String(benign); got != benign {
		t.Errorf("look-alikes were altered: %q", got)
	}
}
