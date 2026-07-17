package sharing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func testConfig() *Config {
	return &Config{
		Addr:         "127.0.0.1:8081",
		BaseURL:      "https://share.example.org",
		clientID:     "id",
		clientSecret: "secret",
		host:         "share.example.org",
		sessionKey:   sha256.Sum256([]byte("test-session-key")),
	}
}

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := db.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqldb, err := gdb.DB(); err == nil {
			_ = sqldb.Close()
		}
	})
	return gdb
}

func TestSessionRoundTrip(t *testing.T) {
	c := testConfig()
	in := session{Login: "octocat", RepoIDs: []uint{1, 2, 3}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	sealed, err := c.seal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if out.Login != in.Login || len(out.RepoIDs) != 3 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestSessionExpired(t *testing.T) {
	c := testConfig()
	sealed, err := c.seal(session{Login: "x", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.open(sealed); err == nil {
		t.Fatal("expected expired session to be rejected")
	}
}

func TestSessionTamperRejected(t *testing.T) {
	c := testConfig()
	sealed, err := c.seal(session{Login: "x", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the ciphertext (decode first so the mutation is not
	// lost in unused trailing bits of the last base64 character); the GCM tag
	// must then fail to authenticate.
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xFF
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := c.open(tampered); err == nil {
		t.Fatal("expected tampered session to be rejected")
	}
	// A session sealed under a different key must not open under ours.
	other := testConfig()
	other.sessionKey = sha256.Sum256([]byte("different-key"))
	otherSealed, _ := other.seal(session{Login: "x", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if _, err := c.open(otherSealed); err == nil {
		t.Fatal("expected foreign-key session to be rejected")
	}
}

func TestFetchMaintainedReposFiltersByPermission(t *testing.T) {
	page := []githubRepo{
		{FullName: "o/admin", HTMLURL: "https://github.com/o/admin"},
		{FullName: "o/maintain", HTMLURL: "https://github.com/o/maintain"},
		{FullName: "o/push", HTMLURL: "https://github.com/o/push"},
		{FullName: "o/readonly", HTMLURL: "https://github.com/o/readonly"},
	}
	page[0].Permissions.Admin = true
	page[1].Permissions.Maintain = true
	page[2].Permissions.Push = true
	// page[3] has no elevated permission and must be dropped.

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// One short page ends pagination.
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer srv.Close()

	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	repos, err := fetchMaintainedRepos(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 3 {
		t.Fatalf("expected 3 maintained repos, got %d: %+v", len(repos), repos)
	}
	for _, r := range repos {
		if r.FullName == "o/readonly" {
			t.Fatalf("read-only repo leaked into maintained set")
		}
	}
}

func TestResolveScopeIntersectsByURL(t *testing.T) {
	gdb := openTestDB(t)
	// scrutineer knows these two repos.
	owned := db.Repository{URL: "https://github.com/o/owned.git", Name: "owned", HTMLURL: "https://github.com/o/owned"}
	other := db.Repository{URL: "https://github.com/o/other", Name: "other"}
	if err := gdb.Create(&owned).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&other).Error; err != nil {
		t.Fatal(err)
	}

	// GitHub says the visitor maintains "owned" (different casing / .git) and a
	// repo scrutineer has never seen.
	gh := []githubRepo{
		{HTMLURL: "https://github.com/O/Owned", CloneURL: "https://github.com/o/owned.git"},
		{HTMLURL: "https://github.com/o/unknown", CloneURL: "https://github.com/o/unknown.git"},
	}
	scope, err := resolveScope(context.Background(), gdb, gh)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.ReadOnly {
		t.Fatal("scope must be read-only")
	}
	if _, ok := scope.RepoIDs[owned.ID]; !ok {
		t.Fatalf("expected owned repo %d in scope: %+v", owned.ID, scope.RepoIDs)
	}
	if _, ok := scope.RepoIDs[other.ID]; ok {
		t.Fatal("unmaintained repo leaked into scope")
	}
	if len(scope.RepoIDs) != 1 {
		t.Fatalf("expected exactly one repo in scope, got %d", len(scope.RepoIDs))
	}
}
