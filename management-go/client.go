// Package gap provides a Go client for the GAP Management API.
package gap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// Client is an API client for the GAP Management API.
type Client struct {
	baseURL    string
	passcode   string
	httpClient *http.Client
}

// Option is a functional option for configuring a Client.
type Option func(*Client)

// NewClient creates a new Client targeting the given baseURL (e.g. "http://localhost:9080").
// Additional options can be provided to configure authentication and TLS.
func NewClient(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithPasscode sets the passcode (pre-hashed password) used in the Authorization header.
// The server expects `Bearer <sha512-of-password>`.
func WithPasscode(passcode string) Option {
	return func(c *Client) {
		c.passcode = passcode
	}
}

// WithHTTPClient replaces the default *http.Client with the provided one.
// Use this for full control over TLS, timeouts, and transport.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithCACert configures the client to trust the PEM-encoded CA certificate at certPath.
// This is useful when the GAP server uses a self-signed CA for its management API TLS.
// On error (file not found, invalid PEM) the option silently no-ops; use WithHTTPClient
// for finer-grained error handling.
func WithCACert(certPath string) Option {
	return func(c *Client) {
		caCert, err := os.ReadFile(certPath)
		if err != nil {
			return // silently fail — caller can use WithHTTPClient for more control
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}
	}
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

// doRequest builds and executes an HTTP request. body may be nil.
func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	fullURL, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return nil, fmt.Errorf("building url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if c.passcode != "" {
		req.Header.Set("Authorization", "Bearer "+c.passcode)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	return resp, nil
}

// doGet performs GET path.
func (c *Client) doGet(ctx context.Context, path string) (*http.Response, error) {
	return c.doRequest(ctx, http.MethodGet, path, nil)
}

// doPost marshals body to JSON and performs POST path.
func (c *Client) doPost(ctx context.Context, path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling body: %w", err)
	}
	return c.doRequest(ctx, http.MethodPost, path, bytes.NewReader(data))
}

// doPut marshals body to JSON and performs PUT path.
func (c *Client) doPut(ctx context.Context, path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling body: %w", err)
	}
	return c.doRequest(ctx, http.MethodPut, path, bytes.NewReader(data))
}

// doDelete performs DELETE path.
func (c *Client) doDelete(ctx context.Context, path string) (*http.Response, error) {
	return c.doRequest(ctx, http.MethodDelete, path, nil)
}

// doPatch marshals body to JSON and performs PATCH path.
func (c *Client) doPatch(ctx context.Context, path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling body: %w", err)
	}
	return c.doRequest(ctx, http.MethodPatch, path, bytes.NewReader(data))
}

// decodeResponse reads the response body, checks the status code, and unmarshals
// the JSON body into target on success (2xx). Non-2xx responses return *APIError.
// For 204 No Content, target is left untouched.
func (c *Client) decodeResponse(resp *http.Response, target any) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	// 204 No Content — nothing to unmarshal.
	if resp.StatusCode == http.StatusNoContent || len(body) == 0 {
		return nil
	}

	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

// decodeEmptyResponse checks the status code and returns *APIError for non-2xx.
// Used for endpoints that return no body (e.g., DELETE returning 200/204 with no JSON).
func (c *Client) decodeEmptyResponse(resp *http.Response) error {
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}
	return nil
}

// doSSE sets the Accept: text/event-stream header and returns the response without
// reading the body. The caller is responsible for closing resp.Body.
func (c *Client) doSSE(ctx context.Context, path string) (*http.Response, error) {
	fullURL, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return nil, fmt.Errorf("building url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	if c.passcode != "" {
		req.Header.Set("Authorization", "Bearer "+c.passcode)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	return resp, nil
}
