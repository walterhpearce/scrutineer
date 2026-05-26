package web

import "testing"

func TestLocationURL(t *testing.T) {
	cases := []struct {
		html, commit, loc, want string
	}{
		{"https://github.com/a/b", "abc123", "lib/x.rb:10",
			"https://github.com/a/b/blob/abc123/lib/x.rb#L10"},
		{"https://github.com/a/b", "abc123", "lib/x.rb:10-20",
			"https://github.com/a/b/blob/abc123/lib/x.rb#L10-L20"},
		{"https://github.com/a/b", "abc123", "lib/x.rb",
			"https://github.com/a/b/blob/abc123/lib/x.rb"},
		{"https://gitlab.com/a/b", "abc123", "src/y.go:5-9",
			"https://gitlab.com/a/b/-/blob/abc123/src/y.go#L5-9"},
		{"https://codeberg.org/a/b", "abc123", "./z.c:1",
			"https://codeberg.org/a/b/src/commit/abc123/z.c#L1"},
		{"https://codeberg.org/a/b", "abc123", "src/y.go:5-9",
			"https://codeberg.org/a/b/src/commit/abc123/src/y.go#L5-L9"},
		// SARIF imports append a column ("path:line:col"); the column is
		// dropped and the link still anchors to the line.
		{"https://github.com/a/b", "abc123", "src/handlers/echo.js:42:7",
			"https://github.com/a/b/blob/abc123/src/handlers/echo.js#L42"},
		{"https://gitlab.com/a/b", "abc123", "src/y.go:5-9:3",
			"https://gitlab.com/a/b/-/blob/abc123/src/y.go#L5-9"},
		{"", "abc", "x:1", ""},
		{"https://github.com/a/b", "", "x:1", ""},
		{"https://example.com/a/b", "abc", "x:1", ""},
		// Host detection must use the parsed hostname, not substring match,
		// so a forge name appearing in the path doesn't trigger a link.
		{"https://example.com/github.com/a/b", "abc", "x:1", ""},
		{"https://example.com/gitlab.com/a/b", "abc", "x:1", ""},
	}
	for _, c := range cases {
		if got := locationURL(c.html, c.commit, c.loc); got != c.want {
			t.Errorf("locationURL(%q,%q,%q) = %q, want %q", c.html, c.commit, c.loc, got, c.want)
		}
	}
}
