package gap_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gap "github.com/mikekelly/gap/management-go"
)

// newTestClientForServer creates a client pointing at the given test server.
func newTestClientForServer(t *testing.T, server *httptest.Server, opts ...gap.Option) *gap.Client {
	t.Helper()
	allOpts := append([]gap.Option{gap.WithPasscode("test-passcode")}, opts...)
	return gap.NewClient(server.URL, allOpts...)
}

// ── buildPath tests ────────────────────────────────────────────────────────

func TestBuildPath_NoNamespace(t *testing.T) {
	// When no namespace/scope configured, paths are returned unchanged.
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"plugins": []any{}})
	}))
	defer srv.Close()

	c := gap.NewClient(srv.URL)
	ctx := context.Background()
	c.ListPlugins(ctx) //nolint:errcheck — we only care about path

	if capturedPath != "/plugins" {
		t.Errorf("expected /plugins, got %q", capturedPath)
	}
}

func TestBuildPath_WithNamespaceAndScope(t *testing.T) {
	// When namespace and scope are configured, paths are prefixed.
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"plugins": []any{}})
	}))
	defer srv.Close()

	c := gap.NewClient(srv.URL,
		gap.WithNamespace("myns"),
		gap.WithScope("myscope"),
	)
	ctx := context.Background()
	c.ListPlugins(ctx) //nolint:errcheck — we only care about path

	want := "/namespaces/myns/scopes/myscope/plugins"
	if capturedPath != want {
		t.Errorf("expected %q, got %q", want, capturedPath)
	}
}

func TestBuildPath_OnlyNamespace_NoPrefix(t *testing.T) {
	// When only namespace is set (but not scope), path is NOT prefixed.
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"plugins": []any{}})
	}))
	defer srv.Close()

	c := gap.NewClient(srv.URL, gap.WithNamespace("myns"))
	ctx := context.Background()
	c.ListPlugins(ctx) //nolint:errcheck

	if capturedPath != "/plugins" {
		t.Errorf("expected /plugins (no prefix when scope missing), got %q", capturedPath)
	}
}

func TestBuildPath_OnlyScope_NoPrefix(t *testing.T) {
	// When only scope is set (but not namespace), path is NOT prefixed.
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"plugins": []any{}})
	}))
	defer srv.Close()

	c := gap.NewClient(srv.URL, gap.WithScope("myscope"))
	ctx := context.Background()
	c.ListPlugins(ctx) //nolint:errcheck

	if capturedPath != "/plugins" {
		t.Errorf("expected /plugins (no prefix when namespace missing), got %q", capturedPath)
	}
}

// ── Namespace discovery tests ──────────────────────────────────────────────

func TestListNamespaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/namespaces" {
			t.Errorf("unexpected path %q", r.URL.Path)
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"namespaces": []string{"ns1", "ns2"},
		})
	}))
	defer srv.Close()

	c := newTestClientForServer(t, srv)
	ctx := context.Background()
	result, err := c.ListNamespaces(ctx)
	if err != nil {
		t.Fatalf("ListNamespaces error: %v", err)
	}
	if len(result) != 2 || result[0] != "ns1" || result[1] != "ns2" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestGetNamespaceScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/namespaces/myns/scopes" {
			t.Errorf("unexpected path %q", r.URL.Path)
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"namespace": "myns",
			"scopes":    []string{"scope1", "scope2"},
		})
	}))
	defer srv.Close()

	c := newTestClientForServer(t, srv)
	ctx := context.Background()
	result, err := c.GetNamespaceScopes(ctx, "myns")
	if err != nil {
		t.Fatalf("GetNamespaceScopes error: %v", err)
	}
	if len(result) != 2 || result[0] != "scope1" || result[1] != "scope2" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestGetScopeInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/namespaces/myns/scopes/myscope" {
			t.Errorf("unexpected path %q", r.URL.Path)
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"namespace": "myns",
			"scope":     "myscope",
			"resources": map[string]any{
				"plugins":     3,
				"tokens":      7,
				"header_sets": 2,
			},
		})
	}))
	defer srv.Close()

	c := newTestClientForServer(t, srv)
	ctx := context.Background()
	result, err := c.GetScopeInfo(ctx, "myns", "myscope")
	if err != nil {
		t.Fatalf("GetScopeInfo error: %v", err)
	}
	if result.Namespace != "myns" {
		t.Errorf("expected Namespace=myns, got %q", result.Namespace)
	}
	if result.Scope != "myscope" {
		t.Errorf("expected Scope=myscope, got %q", result.Scope)
	}
	if result.Resources.Plugins != 3 {
		t.Errorf("expected Plugins=3, got %d", result.Resources.Plugins)
	}
	if result.Resources.Tokens != 7 {
		t.Errorf("expected Tokens=7, got %d", result.Resources.Tokens)
	}
	if result.Resources.HeaderSets != 2 {
		t.Errorf("expected HeaderSets=2, got %d", result.Resources.HeaderSets)
	}
}

// ── buildPath does NOT affect namespace discovery endpoints ───────────────

func TestNamespaceDiscoveryDoesNotUseBuildPath(t *testing.T) {
	// Even when namespace+scope configured, discovery endpoints are top-level.
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{
			"namespaces": []string{},
		})
	}))
	defer srv.Close()

	c := gap.NewClient(srv.URL,
		gap.WithNamespace("myns"),
		gap.WithScope("myscope"),
	)
	ctx := context.Background()
	c.ListNamespaces(ctx) //nolint:errcheck

	if capturedPath != "/namespaces" {
		t.Errorf("namespace discovery should be top-level, got %q", capturedPath)
	}
}
