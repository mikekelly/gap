package gap

import (
	"context"
	"fmt"
	"io"
	"net/url"
)

// QueryManagementLog queries the management audit log with optional filters.
// GET /management-log?operation=...&resource_type=...&resource_id=...&success=...&since=...&limit=...
// Pass nil for no filters.
func (c *Client) QueryManagementLog(ctx context.Context, query *ManagementLogQuery) (*ManagementLogResponse, error) {
	path := c.buildPath("/management-log")
	if query != nil {
		params := url.Values{}
		if query.Operation != nil {
			params.Set("operation", *query.Operation)
		}
		if query.ResourceType != nil {
			params.Set("resource_type", *query.ResourceType)
		}
		if query.ResourceID != nil {
			params.Set("resource_id", *query.ResourceID)
		}
		if query.Success != nil {
			if *query.Success {
				params.Set("success", "true")
			} else {
				params.Set("success", "false")
			}
		}
		if query.Since != nil {
			params.Set("since", *query.Since)
		}
		if query.Limit != nil {
			params.Set("limit", fmt.Sprintf("%d", *query.Limit))
		}
		if encoded := params.Encode(); encoded != "" {
			path += "?" + encoded
		}
	}
	resp, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	var result ManagementLogResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StreamManagementLog opens an SSE stream for real-time management log events.
// GET /management-log/stream
// The returned EventStream must be closed by the caller.
func (c *Client) StreamManagementLog(ctx context.Context) (*EventStream[ManagementLogEntry], error) {
	resp, err := c.doSSE(ctx, c.buildPath("/management-log/stream"))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Message: string(body)}
	}
	return newEventStream[ManagementLogEntry](resp), nil
}
