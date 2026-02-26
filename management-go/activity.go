package gap

import (
	"context"
	"fmt"
	"io"
	"net/url"
)

// QueryActivity queries the activity log with optional filters.
// GET /activity?domain=...&path=...&plugin=...&agent=...&method=...&since=...&request_id=...&limit=...
// Pass nil for no filters.
func (c *Client) QueryActivity(ctx context.Context, query *ActivityQuery) (*ActivityResponse, error) {
	path := "/activity"
	if query != nil {
		params := url.Values{}
		if query.Domain != nil {
			params.Set("domain", *query.Domain)
		}
		if query.Path != nil {
			params.Set("path", *query.Path)
		}
		if query.PluginID != nil {
			params.Set("plugin", *query.PluginID)
		}
		if query.Agent != nil {
			params.Set("agent", *query.Agent)
		}
		if query.Method != nil {
			params.Set("method", *query.Method)
		}
		if query.Since != nil {
			params.Set("since", *query.Since)
		}
		if query.RequestID != nil {
			params.Set("request_id", *query.RequestID)
		}
		if query.Limit != nil {
			params.Set("limit", fmt.Sprintf("%d", *query.Limit))
		}
		if encoded := params.Encode(); encoded != "" {
			path += "?" + encoded
		}
	}
	resp, err := c.doGet(ctx, c.buildPath(path))
	if err != nil {
		return nil, err
	}
	var result ActivityResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetRequestDetails returns detailed request/response information for a specific request.
// GET /activity/:request_id/details
func (c *Client) GetRequestDetails(ctx context.Context, requestID string) (*RequestDetails, error) {
	path := c.buildPath("/activity/" + url.PathEscape(requestID) + "/details")
	resp, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	var result RequestDetails
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StreamActivity opens an SSE stream for real-time activity events.
// GET /activity/stream
// The returned EventStream must be closed by the caller.
func (c *Client) StreamActivity(ctx context.Context) (*EventStream[ActivityEntry], error) {
	resp, err := c.doSSE(ctx, c.buildPath("/activity/stream"))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Message: string(body)}
	}
	return newEventStream[ActivityEntry](resp), nil
}
