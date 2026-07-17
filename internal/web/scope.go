package web

import (
	"context"
	"net/http"

	"gorm.io/gorm"
)

// ViewScope optionally restricts a request to a set of repositories and marks
// it read-only. It is the single, auth-agnostic seam the sharing binary
// (cmd/sharing) uses to reuse the main UI for external maintainers: this
// package knows only that a request may carry an allow-list of repository IDs
// and a read-only flag, never who set it or why. When no scope is present —
// the default for the main app — every consulting site behaves exactly as it
// did before, so the local operator experience is unchanged.
type ViewScope struct {
	// RepoIDs is the set of repository IDs the request may see. A present
	// scope with an empty set means "no repositories" (matches nothing),
	// not "all repositories".
	RepoIDs map[uint]struct{}
	// ReadOnly hides mutating controls in rendered pages via the template
	// "Sharing" flag (see render and isReadOnly).
	ReadOnly bool
}

type viewScopeKey struct{}

// WithViewScope returns a child context carrying sc. Exported so cmd/sharing
// can attach a scope before forwarding a request into the reused handler.
func WithViewScope(ctx context.Context, sc ViewScope) context.Context {
	return context.WithValue(ctx, viewScopeKey{}, sc)
}

// viewScopeFrom returns the request's scope and whether one was set.
func viewScopeFrom(r *http.Request) (ViewScope, bool) {
	sc, ok := r.Context().Value(viewScopeKey{}).(ViewScope)
	return sc, ok
}

// isReadOnly reports whether the request runs under a read-only scope. Drives
// the template "Sharing" flag that gates admin nav and mutating controls.
func isReadOnly(r *http.Request) bool {
	sc, ok := viewScopeFrom(r)
	return ok && sc.ReadOnly
}

// scopeIDs returns the allow-listed IDs as a slice for an IN clause.
func (sc ViewScope) scopeIDs() []uint {
	ids := make([]uint, 0, len(sc.RepoIDs))
	for id := range sc.RepoIDs {
		ids = append(ids, id)
	}
	return ids
}

// applyRepoScope constrains q to the request's allow-listed repositories,
// filtering on col (e.g. "repository_id" for a findings query, "id" for a
// repositories query). It is a no-op when the request carries no scope, so the
// main app's list pages are unaffected. When a scope is present but empty the
// query is forced to match nothing (GORM renders IN (NULL) for the empty
// slice), which is the correct behaviour for a maintainer with no known repos.
func applyRepoScope(q *gorm.DB, r *http.Request, col string) *gorm.DB {
	sc, ok := viewScopeFrom(r)
	if !ok {
		return q
	}
	return q.Where(col+" IN ?", sc.scopeIDs())
}
