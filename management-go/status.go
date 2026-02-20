package gap

import "context"

// Status returns the server status. No auth required.
// GET /status
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	resp, err := c.doGet(ctx, "/status")
	if err != nil {
		return nil, err
	}
	var result StatusResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Init initializes the server with the given password hash.
// POST /init — no auth required (only works on uninitialized server)
func (c *Client) Init(ctx context.Context, req *InitRequest) (*InitResponse, error) {
	resp, err := c.doPost(ctx, "/init", req)
	if err != nil {
		return nil, err
	}
	var result InitResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
