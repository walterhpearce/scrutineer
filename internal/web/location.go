package web

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// locationURL turns a finding location ("path/to/file.rb:12-34") into a blob
// link on the upstream forge, anchored to the line range. Returns "" when we
// don't have enough to build one (no html_url, no commit, unrecognised host).
//
// Host matching parses htmlURL and compares against u.Hostname() so a path
// segment like ".../github.com/..." on an unrelated host can't be mistaken
// for the real forge.
func locationURL(htmlURL, commit, location string) string {
	if htmlURL == "" || commit == "" || location == "" {
		return ""
	}
	path, frag := splitLocation(location)
	if path == "" {
		return ""
	}
	u, err := url.Parse(htmlURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	base := strings.TrimSuffix(htmlURL, "/")
	switch {
	case host == "github.com":
		u := fmt.Sprintf("%s/blob/%s/%s", base, commit, path)
		if frag != "" {
			u += "#" + githubFragment(frag)
		}
		return u
	case host == "codeberg.org":
		// Codeberg runs Gitea, which uses /src/commit/{sha}/ for blob views.
		// Line anchors use the same L1 / L1-L5 shape as GitHub.
		u := fmt.Sprintf("%s/src/commit/%s/%s", base, commit, path)
		if frag != "" {
			u += "#" + githubFragment(frag)
		}
		return u
	case strings.HasPrefix(host, "gitlab."):
		u := fmt.Sprintf("%s/-/blob/%s/%s", base, commit, path)
		if frag != "" {
			u += "#" + gitlabFragment(frag)
		}
		return u
	}
	return ""
}

// locRE splits a finding location into its file path and line spec. The
// trailing column group is optional so importer-supplied locations that carry
// a column ("file.js:42:7", as emitted by the SARIF parser) resolve to the
// same blob link as native "file.rb:12-34" locations.
var locRE = regexp.MustCompile(`^(.*?):(\d+(?:-\d+)?)(?::\d+(?:-\d+)?)?$`)

func splitLocation(loc string) (path, lines string) {
	loc = strings.TrimPrefix(strings.TrimSpace(loc), "./")
	if m := locRE.FindStringSubmatch(loc); m != nil {
		return m[1], m[2]
	}
	return loc, ""
}

func githubFragment(lines string) string {
	if a, b, ok := strings.Cut(lines, "-"); ok {
		return "L" + a + "-L" + b
	}
	return "L" + lines
}

func gitlabFragment(lines string) string {
	if a, b, ok := strings.Cut(lines, "-"); ok {
		return "L" + a + "-" + b
	}
	return "L" + lines
}
