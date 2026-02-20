package gap

import (
	"context"
	"fmt"
)

// ListTokens returns all agent tokens.
// GET /tokens
func (c *Client) ListTokens(ctx context.Context) (*TokensResponse, error) {
	resp, err := c.doGet(ctx, "/tokens")
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
// POST /tokens/create
func (c *Client) CreateToken(ctx context.Context, req *CreateTokenRequest) (*TokenResponse, error) {
	resp, err := c.doPost(ctx, "/tokens/create", req)
	if err != nil {
		return nil, err
	}
	var result TokenResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeToken revokes the token with the given ID.
// DELETE /tokens/:id
func (c *Client) RevokeToken(ctx context.Context, id string) (*RevokeTokenResponse, error) {
	path := fmt.Sprintf("/tokens/%s", id)
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
