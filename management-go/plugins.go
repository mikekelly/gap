package gap

import (
	"context"
	"net/url"
)

// ListPlugins returns all installed plugins.
// GET /plugins
func (c *Client) ListPlugins(ctx context.Context) (*PluginsResponse, error) {
	resp, err := c.doGet(ctx, c.buildPath("/plugins"))
	if err != nil {
		return nil, err
	}
	var result PluginsResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// InstallPlugin installs a plugin from GitHub.
// POST /plugins/install
func (c *Client) InstallPlugin(ctx context.Context, req *InstallRequest) (*InstallResponse, error) {
	resp, err := c.doPost(ctx, c.buildPath("/plugins/install"), req)
	if err != nil {
		return nil, err
	}
	var result InstallResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RegisterPlugin registers a plugin with inline code.
// POST /plugins/register
func (c *Client) RegisterPlugin(ctx context.Context, req *RegisterPluginRequest) (*RegisterResponse, error) {
	resp, err := c.doPost(ctx, c.buildPath("/plugins/register"), req)
	if err != nil {
		return nil, err
	}
	var result RegisterResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UninstallPlugin removes a plugin.
// DELETE /plugins/:id
func (c *Client) UninstallPlugin(ctx context.Context, id string) (*UninstallResponse, error) {
	path := c.buildPath("/plugins/" + url.PathEscape(id))
	resp, err := c.doDelete(ctx, path)
	if err != nil {
		return nil, err
	}
	var result UninstallResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdatePlugin triggers a GitHub-based plugin update.
// POST /plugins/:id/update
func (c *Client) UpdatePlugin(ctx context.Context, id string) (*UpdateResponse, error) {
	path := c.buildPath("/plugins/" + url.PathEscape(id) + "/update")
	resp, err := c.doPost(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	var result UpdateResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdatePluginConfig updates a plugin's weight.
// PATCH /plugins/:id
func (c *Client) UpdatePluginConfig(ctx context.Context, id string, req *UpdatePluginRequest) (*UpdatePluginResponse, error) {
	path := c.buildPath("/plugins/" + url.PathEscape(id))
	resp, err := c.doPatch(ctx, path, req)
	if err != nil {
		return nil, err
	}
	var result UpdatePluginResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
