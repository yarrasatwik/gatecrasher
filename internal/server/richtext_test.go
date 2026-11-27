package server

import "testing"

func TestRichTextEscapesAndFormats(t *testing.T) {
	cases := map[string]string{
		"Mark `payment_config` Server-side only": "Mark <code>payment_config</code> Server-side only",
		"<script>alert(1)</script> `x<y`":        "&lt;script&gt;alert(1)&lt;/script&gt; <code>x&lt;y</code>",
		"dangling `tick":                         "dangling `tick",
		"plain":                                  "plain",
	}
	for in, want := range cases {
		if got := string(richText(in)); got != want {
			t.Errorf("richText(%q) = %q, want %q", in, got, want)
		}
	}
}
