package gap

import (
	"context"
	"net/url"
)

// SetCredential sets a credential value for a plugin.
// POST /credentials/:plugin_id/:key
func (c *Client) SetCredential(ctx context.Context, pluginID, key string, req *SetCredentialRequest) (*SetCredentialResponse, error) {
	path := "/credentials/" + url.PathEscape(pluginID) + "/" + url.PathEscape(key)
	resp, err := c.doPost(ctx, path, req)
	if err != nil {
		return nil, err
	}
	var result SetCredentialResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteCredential removes a credential for a plugin.
// DELETE /credentials/:plugin_id/:key — returns 200 with no body
func (c *Client) DeleteCredential(ctx context.Context, pluginID, key string) error {
	path := "/credentials/" + url.PathEscape(pluginID) + "/" + url.PathEscape(key)
	resp, err := c.doDelete(ctx, path)
	if err != nil {
		return err
	}
	return c.decodeEmptyResponse(resp)
}
