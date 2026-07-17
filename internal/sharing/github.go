package sharing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scrutineer/internal/httpx"
)

// githubAPI is the API base. A var, not a const, so tests can point the client
// at an httptest.Server, mirroring internal/web/org_import.go.
var githubAPI = "https://api.github.com"

const (
	githubUA       = "scrutineer-sharing"
	githubPerPage  = 100
	githubMaxPages = 100
	githubTimeout  = 30 * time.Second
	maxGitHubBody  = 25 * 1024 * 1024
)

// githubUser is the slice of GET /user the portal needs.
type githubUser struct {
	Login string `json:"login"`
}

// githubRepo is the slice of GET /user/repos the portal needs: the identifiers
// used to intersect with scrutineer's repositories and the effective
// permission used to decide whether the visitor maintains the repo.
type githubRepo struct {
	FullName    string `json:"full_name"`
	HTMLURL     string `json:"html_url"`
	CloneURL    string `json:"clone_url"`
	Permissions struct {
		Admin    bool `json:"admin"`
		Maintain bool `json:"maintain"`
		Push     bool `json:"push"`
	} `json:"permissions"`
}

// maintained reports whether the visitor's effective permission on the repo is
// enough to be considered a maintainer (admin, maintain, or push/write).
func (r githubRepo) maintained() bool {
	return r.Permissions.Admin || r.Permissions.Maintain || r.Permissions.Push
}

// fetchUser returns the authenticated visitor's GitHub login.
func fetchUser(ctx context.Context, token string) (string, error) {
	var u githubUser
	if err := githubGet(ctx, token, githubAPI+"/user", &u); err != nil {
		return "", err
	}
	if u.Login == "" {
		return "", fmt.Errorf("sharing: GitHub returned an empty login")
	}
	return u.Login, nil
}

// fetchMaintainedRepos lists every repository the visitor can push to,
// maintain, or administer, paging to completion.
func fetchMaintainedRepos(ctx context.Context, token string) ([]githubRepo, error) {
	ctx, cancel := context.WithTimeout(ctx, githubTimeout)
	defer cancel()

	var maintained []githubRepo
	for page := 1; page <= githubMaxPages; page++ {
		q := url.Values{
			"per_page":    {fmt.Sprint(githubPerPage)},
			"page":        {fmt.Sprint(page)},
			"affiliation": {"owner,collaborator,organization_member"},
		}
		var batch []githubRepo
		if err := githubGet(ctx, token, githubAPI+"/user/repos?"+q.Encode(), &batch); err != nil {
			return nil, err
		}
		for _, r := range batch {
			if r.maintained() {
				maintained = append(maintained, r)
			}
		}
		// A short page is the last page.
		if len(batch) < githubPerPage {
			break
		}
	}
	return maintained, nil
}

// githubGet issues an authenticated GET and decodes a JSON response into dst.
func githubGet(ctx context.Context, token, endpoint string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", githubUA)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpx.DoRetry(req, httpx.RetryOptions{})
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubBody))
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sharing: GitHub API returned %d for %s", resp.StatusCode, endpointPath(endpoint))
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("sharing: decode GitHub response: %w", err)
	}
	return nil
}

// endpointPath strips the query string so error messages don't echo tokens
// (there are none in the query today, but this keeps it safe if that changes).
func endpointPath(endpoint string) string {
	if i := strings.IndexByte(endpoint, '?'); i >= 0 {
		return endpoint[:i]
	}
	return endpoint
}
