package gap

import "time"

// ── Status / Init ────────────────────────────────────────────────────────────

// StatusResponse is returned by GET /status. No auth required.
type StatusResponse struct {
	Version        string `json:"version"`
	UptimeSeconds  uint64 `json:"uptime_seconds"`
	ProxyPort      uint16 `json:"proxy_port"`
	APIPort        uint16 `json:"api_port"`
	Initialized    bool   `json:"initialized"`
}

// InitRequest is sent to POST /init to set the server password.
// PasswordHash must be the SHA-512 hex digest of the plaintext password.
type InitRequest struct {
	PasswordHash string `json:"password_hash"`
}

// InitResponse is returned by POST /init.
type InitResponse struct {
	CAPath string `json:"ca_path"`
}

// ── Plugins ──────────────────────────────────────────────────────────────────

// PluginInfo describes an installed plugin as returned by GET /plugins.
type PluginInfo struct {
	ID               string   `json:"id"`
	MatchPatterns    []string `json:"match_patterns"`
	CredentialSchema []string `json:"credential_schema"`
}

// PluginsResponse is returned by GET /plugins.
type PluginsResponse struct {
	Plugins []PluginInfo `json:"plugins"`
}

// InstallRequest is sent to POST /plugins/install to install a plugin from GitHub.
// Source must be in "owner/repo" format.
type InstallRequest struct {
	Source string `json:"source"`
}

// InstallResponse is returned by POST /plugins/install.
type InstallResponse struct {
	ID        string  `json:"id"`
	Source    string  `json:"source"`
	Installed bool    `json:"installed"`
	CommitSHA *string `json:"commit_sha,omitempty"`
}

// RegisterPluginRequest is sent to POST /plugins/register to register a plugin with inline code.
// The server generates the plugin ID.
type RegisterPluginRequest struct {
	Code string `json:"code"`
}

// RegisterResponse is returned by POST /plugins/register.
type RegisterResponse struct {
	ID         string `json:"id"`
	Registered bool   `json:"registered"`
}

// UninstallResponse is returned by DELETE /plugins/:id.
type UninstallResponse struct {
	ID          string `json:"id"`
	Uninstalled bool   `json:"uninstalled"`
}

// UpdateResponse is returned by POST /plugins/:id/update (GitHub update).
type UpdateResponse struct {
	ID        string  `json:"id"`
	Updated   bool    `json:"updated"`
	CommitSHA *string `json:"commit_sha,omitempty"`
}

// UpdatePluginRequest is sent to PATCH /plugins/:id to update the plugin weight.
type UpdatePluginRequest struct {
	Weight int `json:"weight"`
}

// UpdatePluginResponse is returned by PATCH /plugins/:id.
type UpdatePluginResponse struct {
	ID      string `json:"id"`
	Updated bool   `json:"updated"`
}

// ── Tokens ───────────────────────────────────────────────────────────────────

// TokenScope defines a permitted host/path/method pattern for scoped tokens.
// JSON can be either a string ("example.com/v1/*") or an object ({"match": "...", "methods": [...]}).
// The Go client always uses the struct form.
type TokenScope struct {
	HostPattern string   `json:"host_pattern"`
	Port        *uint16  `json:"port,omitempty"`
	PathPattern string   `json:"path_pattern"`
	Methods     []string `json:"methods,omitempty"`
}

// CreateTokenRequest is sent to POST /tokens.
type CreateTokenRequest struct {
	Permitted []TokenScope `json:"permitted,omitempty"`
}

// TokenResponse represents an agent token. The Token field is only populated
// on creation (POST /tokens); list responses omit it.
type TokenResponse struct {
	Prefix    string       `json:"prefix"`
	Token     *string      `json:"token,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	Permitted []TokenScope `json:"permitted,omitempty"`
	RevokedAt *time.Time   `json:"revoked_at,omitempty"`
}

// TokensResponse is returned by GET /tokens.
type TokensResponse struct {
	Tokens []TokenResponse `json:"tokens"`
}

// RevokeTokenResponse is returned by DELETE /tokens/{prefix}.
type RevokeTokenResponse struct {
	Prefix  string `json:"prefix"`
	Revoked bool   `json:"revoked"`
}

// ── Credentials ──────────────────────────────────────────────────────────────

// SetCredentialRequest is sent to POST /credentials/:plugin_id/:key.
type SetCredentialRequest struct {
	Value string `json:"value"`
}

// SetCredentialResponse is returned by POST /credentials/:plugin_id/:key.
type SetCredentialResponse struct {
	PluginID string `json:"plugin_id"`
	Key      string `json:"key"`
	Set      bool   `json:"set"`
}

// ── Header Sets ──────────────────────────────────────────────────────────────

// CreateHeaderSetRequest is sent to POST /header-sets.
// Headers is an optional map of header name -> value to set immediately.
type CreateHeaderSetRequest struct {
	MatchPatterns []string          `json:"match_patterns"`
	Weight        int               `json:"weight,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// CreateHeaderSetResponse is returned by POST /header-sets.
type CreateHeaderSetResponse struct {
	ID      string `json:"id"`
	Created bool   `json:"created"`
}

// UpdateHeaderSetRequest is sent to PATCH /header-sets/:id.
// At least one field must be set.
type UpdateHeaderSetRequest struct {
	MatchPatterns *[]string `json:"match_patterns,omitempty"`
	Weight        *int      `json:"weight,omitempty"`
}

// HeaderSetListItem is one entry in the header-sets list. Headers contains
// only the header names (no values are exposed).
type HeaderSetListItem struct {
	ID            string   `json:"id"`
	MatchPatterns []string `json:"match_patterns"`
	Weight        int      `json:"weight"`
	Headers       []string `json:"headers"`
}

// HeaderSetListResponse is returned by GET /header-sets.
type HeaderSetListResponse struct {
	HeaderSets []HeaderSetListItem `json:"header_sets"`
}

// SetHeaderRequest is sent to POST /header-sets/:id/headers.
type SetHeaderRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SetHeaderResponse is returned by POST /header-sets/:id/headers.
type SetHeaderResponse struct {
	HeaderSet string `json:"header_set"`
	Header    string `json:"header"`
	Set       bool   `json:"set"`
}

// DeleteHeaderResponse is returned by DELETE /header-sets/:id/headers/:header_name.
type DeleteHeaderResponse struct {
	HeaderSet string `json:"header_set"`
	Header    string `json:"header"`
	Deleted   bool   `json:"deleted"`
}

// UpdateHeaderSetResponse is returned by PATCH /header-sets/:id.
type UpdateHeaderSetResponse struct {
	ID      string `json:"id"`
	Updated bool   `json:"updated"`
}

// DeleteHeaderSetResponse is returned by DELETE /header-sets/:id.
type DeleteHeaderSetResponse struct {
	Deleted bool `json:"deleted"`
}

// ── Activity ─────────────────────────────────────────────────────────────────

// ActivityEntry is a single proxied-request record.
type ActivityEntry struct {
	Timestamp      time.Time `json:"timestamp"`
	RequestID      *string   `json:"request_id,omitempty"`
	Method         string    `json:"method"`
	URL            string    `json:"url"`
	AgentID        *string   `json:"agent_id,omitempty"`
	Status         uint16    `json:"status"`
	PluginID       *string   `json:"plugin_id,omitempty"`
	PluginSHA      *string   `json:"plugin_sha,omitempty"`
	SourceHash     *string   `json:"source_hash,omitempty"`
	RequestHeaders *string   `json:"request_headers,omitempty"`
	RejectionStage  *string  `json:"rejection_stage,omitempty"`
	RejectionReason *string  `json:"rejection_reason,omitempty"`
}

// ActivityResponse is returned by GET /activity.
type ActivityResponse struct {
	Entries []ActivityEntry `json:"entries"`
}

// ActivityQuery holds query parameters for GET /activity.
type ActivityQuery struct {
	Domain    *string `json:"domain,omitempty"`
	Path      *string `json:"path,omitempty"`
	PluginID  *string `json:"plugin_id,omitempty"`
	Agent     *string `json:"agent,omitempty"`
	Method    *string `json:"method,omitempty"`
	Since     *string `json:"since,omitempty"` // ISO 8601
	RequestID *string `json:"request_id,omitempty"`
	Limit     *uint32 `json:"limit,omitempty"`
}

// RequestDetails holds the full request/response detail for one proxied request.
type RequestDetails struct {
	RequestID          string  `json:"request_id"`
	ReqHeaders         *string `json:"req_headers,omitempty"`
	ReqBody            []byte  `json:"req_body,omitempty"`
	TransformedURL     *string `json:"transformed_url,omitempty"`
	TransformedHeaders *string `json:"transformed_headers,omitempty"`
	TransformedBody    []byte  `json:"transformed_body,omitempty"`
	ResponseStatus     *uint16 `json:"response_status,omitempty"`
	ResponseHeaders    *string `json:"response_headers,omitempty"`
	ResponseBody       []byte  `json:"response_body,omitempty"`
	BodyTruncated      bool    `json:"body_truncated"`
}

// ── Namespace Discovery ───────────────────────────────────────────────────────

// ScopeResources holds the per-resource counts returned by GET /namespaces/{ns}/scopes/{scope}.
type ScopeResources struct {
	Plugins    int `json:"plugins"`
	Tokens     int `json:"tokens"`
	HeaderSets int `json:"header_sets"`
}

// ScopeInfoResponse is returned by GET /namespaces/{ns}/scopes/{scope}.
type ScopeInfoResponse struct {
	Namespace string         `json:"namespace"`
	Scope     string         `json:"scope"`
	Resources ScopeResources `json:"resources"`
}

// ── Management Log ───────────────────────────────────────────────────────────

// ManagementLogEntry is one audit-log record.
type ManagementLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	Operation    string    `json:"operation"`
	ResourceType string    `json:"resource_type"`
	ResourceID   *string   `json:"resource_id,omitempty"`
	Detail       *string   `json:"detail,omitempty"`
	Success      bool      `json:"success"`
	ErrorMessage *string   `json:"error_message,omitempty"`
}

// ManagementLogResponse is returned by GET /management-log.
type ManagementLogResponse struct {
	Entries []ManagementLogEntry `json:"entries"`
}

// ManagementLogQuery holds query parameters for GET /management-log.
type ManagementLogQuery struct {
	Operation    *string `json:"operation,omitempty"`
	ResourceType *string `json:"resource_type,omitempty"`
	ResourceID   *string `json:"resource_id,omitempty"`
	Success      *bool   `json:"success,omitempty"`
	Since        *string `json:"since,omitempty"` // ISO 8601
	Limit        *uint32 `json:"limit,omitempty"`
}
