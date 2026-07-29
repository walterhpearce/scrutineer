package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// seedRepoWithFinding creates a repository, a deep-dive scan, and one finding
// whose title is returned so tests can assert on its presence in list pages.
func seedRepoWithFinding(t *testing.T, s *Server, url, name, title string) uint {
	t.Helper()
	repo := db.Repository{URL: url, Name: name}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: title,
		Severity: "High", Location: "x.go:1", CWE: "CWE-79"}).Error; err != nil {
		t.Fatal(err)
	}
	return repo.ID
}

// wants pairs a list path with the substring that must (or must not) appear
// for the alpha/bravo fixtures: findings render titles, the repo list renders
// URLs.
var scopeProbes = map[string][2]string{
	"/findings": {"SSRF in alpha", "XSS in bravo"},
	"/":         {"example.com/a", "example.com/b"},
}

// TestViewScope_unsetIsNoop confirms the main app (no scope on the request)
// still sees every repository and finding — the seam must be inert by default.
func TestViewScope_unsetIsNoop(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedRepoWithFinding(t, s, "https://example.com/a", "alpha", "SSRF in alpha")
	seedRepoWithFinding(t, s, "https://example.com/b", "bravo", "XSS in bravo")

	for path, probe := range scopeProbes {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", path))
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, probe[0]) || !strings.Contains(body, probe[1]) {
			t.Errorf("%s: expected both %q and %q", path, probe[0], probe[1])
		}
	}
}

// TestViewScope_restrictsListsAndSharingFlag confirms a restricted read-only
// scope limits both list pages to the allow-listed repository and turns on the
// Sharing template flag (admin nav hidden).
func TestViewScope_restrictsListsAndSharingFlag(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	a := seedRepoWithFinding(t, s, "https://example.com/a", "alpha", "SSRF in alpha")
	seedRepoWithFinding(t, s, "https://example.com/b", "bravo", "XSS in bravo")

	scope := ViewScope{RepoIDs: map[uint]struct{}{a: {}}, ReadOnly: true}

	for path, probe := range scopeProbes {
		r := localReq("GET", path)
		r = r.WithContext(WithViewScope(r.Context(), scope))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, probe[0]) {
			t.Errorf("%s: in-scope %q missing", path, probe[0])
		}
		if strings.Contains(body, probe[1]) {
			t.Errorf("%s: out-of-scope %q leaked", path, probe[1])
		}
		// Sharing flag hides the Settings gear (admin nav) in the layout.
		if strings.Contains(body, `href="/settings"`) {
			t.Errorf("%s: admin nav not hidden under read-only scope", path)
		}
	}
}

// TestViewScope_readOnlyRefusesWrites confirms the read-only scope refuses the
// mutating finding handlers at the write path itself (defense in depth behind
// the sharing portal's GET-only route whitelist): they return 403 and perform
// no write, rather than relying only on the UI hiding the controls.
func TestViewScope_readOnlyRefusesWrites(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repoID := seedRepoWithFinding(t, s, "https://example.com/a", "alpha", "SSRF in alpha")
	scope := ViewScope{RepoIDs: map[uint]struct{}{repoID: {}}, ReadOnly: true}

	for _, path := range []string{"/findings/1/status", "/findings/1/notes"} {
		r := localReq("POST", path)
		r = r.WithContext(WithViewScope(r.Context(), scope))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s under read-only scope: want 403, got %d", path, w.Code)
		}
	}

	// The finding's status must be untouched by the refused write (still the
	// "new" default it was created with).
	var f db.Finding
	if err := s.DB.First(&f).Error; err != nil {
		t.Fatal(err)
	}
	if f.Status != db.FindingNew {
		t.Errorf("read-only write mutated finding status to %q", f.Status)
	}
}

// TestViewScope_emptyScopeMatchesNothing confirms a present-but-empty scope
// (a maintainer with no known repos) hides everything rather than everything
// being visible.
func TestViewScope_emptyScopeMatchesNothing(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedRepoWithFinding(t, s, "https://example.com/a", "alpha", "SSRF in alpha")

	r := localReq("GET", "/findings")
	r = r.WithContext(WithViewScope(r.Context(), ViewScope{RepoIDs: map[uint]struct{}{}, ReadOnly: true}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "SSRF in alpha") {
		t.Errorf("empty scope leaked a finding")
	}
}
