package gap

import (
	"context"
	"fmt"
	"net/url"
)

// ListHeaderSets returns all header sets.
// GET /header-sets
func (c *Client) ListHeaderSets(ctx context.Context) (*HeaderSetListResponse, error) {
	resp, err := c.doGet(ctx, c.buildPath("/header-sets"))
	if err != nil {
		return nil, err
	}
	var result HeaderSetListResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateHeaderSet creates a new header set.
// POST /header-sets
func (c *Client) CreateHeaderSet(ctx context.Context, req *CreateHeaderSetRequest) (*CreateHeaderSetResponse, error) {
	resp, err := c.doPost(ctx, c.buildPath("/header-sets"), req)
	if err != nil {
		return nil, err
	}
	var result CreateHeaderSetResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateHeaderSet updates a header set's match patterns and/or weight.
// PATCH /header-sets/:id
func (c *Client) UpdateHeaderSet(ctx context.Context, id string, req *UpdateHeaderSetRequest) (*UpdateHeaderSetResponse, error) {
	path := c.buildPath("/header-sets/" + url.PathEscape(id))
	resp, err := c.doPatch(ctx, path, req)
	if err != nil {
		return nil, err
	}
	var result UpdateHeaderSetResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteHeaderSet removes a header set.
// DELETE /header-sets/:id
func (c *Client) DeleteHeaderSet(ctx context.Context, id string) (*DeleteHeaderSetResponse, error) {
	path := c.buildPath("/header-sets/" + url.PathEscape(id))
	resp, err := c.doDelete(ctx, path)
	if err != nil {
		return nil, err
	}
	var result DeleteHeaderSetResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SetHeader sets a header in a header set.
// POST /header-sets/:id/headers
func (c *Client) SetHeader(ctx context.Context, headerSetID string, req *SetHeaderRequest) (*SetHeaderResponse, error) {
	path := c.buildPath("/header-sets/" + url.PathEscape(headerSetID) + "/headers")
	resp, err := c.doPost(ctx, path, req)
	if err != nil {
		return nil, err
	}
	var result SetHeaderResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteHeader removes a header from a header set.
// DELETE /header-sets/:id/headers/:header_name
func (c *Client) DeleteHeader(ctx context.Context, headerSetID, headerName string) (*DeleteHeaderResponse, error) {
	path := c.buildPath(fmt.Sprintf("/header-sets/%s/headers/%s", url.PathEscape(headerSetID), url.PathEscape(headerName)))
	resp, err := c.doDelete(ctx, path)
	if err != nil {
		return nil, err
	}
	var result DeleteHeaderResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
