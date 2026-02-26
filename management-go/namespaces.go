package gap

import (
	"context"
	"fmt"
	"net/url"
)

// ListNamespaces returns all distinct namespaces that have tokens or active plugins.
// GET /namespaces — does NOT use buildPath (top-level endpoint).
func (c *Client) ListNamespaces(ctx context.Context) ([]string, error) {
	resp, err := c.doGet(ctx, "/namespaces")
	if err != nil {
		return nil, err
	}
	var result struct {
		Namespaces []string `json:"namespaces"`
	}
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return result.Namespaces, nil
}

// GetNamespaceScopes returns the distinct scopes within the given namespace.
// GET /namespaces/{ns}/scopes — does NOT use buildPath (top-level endpoint).
func (c *Client) GetNamespaceScopes(ctx context.Context, ns string) ([]string, error) {
	path := fmt.Sprintf("/namespaces/%s/scopes", url.PathEscape(ns))
	resp, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	var result struct {
		Scopes []string `json:"scopes"`
	}
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return result.Scopes, nil
}

// GetScopeInfo returns resource counts for a specific namespace and scope.
// GET /namespaces/{ns}/scopes/{scope} — does NOT use buildPath (top-level endpoint).
func (c *Client) GetScopeInfo(ctx context.Context, ns, scope string) (*ScopeInfoResponse, error) {
	path := fmt.Sprintf("/namespaces/%s/scopes/%s", url.PathEscape(ns), url.PathEscape(scope))
	resp, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	var result ScopeInfoResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
