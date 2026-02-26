package gap

import (
	"context"
	"fmt"
)

// ListTokens returns agent tokens. If includeRevoked is true, revoked tokens are included.
// GET /tokens[?include_revoked=true]
func (c *Client) ListTokens(ctx context.Context, includeRevoked bool) (*TokensResponse, error) {
	path := c.buildPath("/tokens")
	if includeRevoked {
		path += "?include_revoked=true"
	}
	resp, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	var result TokensResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateToken creates a new agent token. The returned TokenResponse includes the
// token value (only available at creation time).
// POST /tokens
func (c *Client) CreateToken(ctx context.Context, req *CreateTokenRequest) (*TokenResponse, error) {
	resp, err := c.doPost(ctx, c.buildPath("/tokens"), req)
	if err != nil {
		return nil, err
	}
	var result TokenResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeToken revokes the token with the given prefix.
// DELETE /tokens/{prefix}
func (c *Client) RevokeToken(ctx context.Context, prefix string) (*RevokeTokenResponse, error) {
	path := c.buildPath(fmt.Sprintf("/tokens/%s", prefix))
	resp, err := c.doDelete(ctx, path)
	if err != nil {
		return nil, err
	}
	var result RevokeTokenResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
