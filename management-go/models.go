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
	Name             string   `json:"name"`
	MatchPatterns    []string `json:"match_patterns"`
	CredentialSchema []string `json:"credential_schema"`
}

// PluginsResponse is returned by GET /plugins.
type PluginsResponse struct {
	Plugins []PluginInfo `json:"plugins"`
}

// InstallRequest is sent to POST /plugins/install to install a plugin from GitHub.
// Name must be in "owner/repo" format.
type InstallRequest struct {
	Name string `json:"name"`
}

// InstallResponse is returned by POST /plugins/install.
type InstallResponse struct {
	Name      string  `json:"name"`
	Installed bool    `json:"installed"`
	CommitSHA *string `json:"commit_sha,omitempty"`
}

// RegisterPluginRequest is sent to POST /plugins/register to register a plugin with inline code.
type RegisterPluginRequest struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

// RegisterResponse is returned by POST /plugins/register.
type RegisterResponse struct {
	Name       string `json:"name"`
	Registered bool   `json:"registered"`
}

// UninstallResponse is returned by DELETE /plugins/:name.
type UninstallResponse struct {
	Name        string `json:"name"`
	Uninstalled bool   `json:"uninstalled"`
}

// UpdateResponse is returned by POST /plugins/:name/update (GitHub update).
type UpdateResponse struct {
	Name      string  `json:"name"`
	Updated   bool    `json:"updated"`
	CommitSHA *string `json:"commit_sha,omitempty"`
}

// UpdatePluginRequest is sent to PATCH /plugins/:name to update the plugin weight.
type UpdatePluginRequest struct {
	Weight int `json:"weight"`
}

// UpdatePluginResponse is returned by PATCH /plugins/:name.
type UpdatePluginResponse struct {
	Name    string `json:"name"`
	Updated bool   `json:"updated"`
}

// ── Tokens ───────────────────────────────────────────────────────────────────

// CreateTokenRequest is sent to POST /tokens/create.
type CreateTokenRequest struct {
	Name string `json:"name"`
}

// TokenResponse represents an agent token. The Token field is only populated
// on creation (POST /tokens/create); list responses omit it.
type TokenResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	Token     *string    `json:"token,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// TokensResponse is returned by GET /tokens.
type TokensResponse struct {
	Tokens []TokenResponse `json:"tokens"`
}

// RevokeTokenResponse is returned by DELETE /tokens/:id.
type RevokeTokenResponse struct {
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

// ── Credentials ──────────────────────────────────────────────────────────────

// SetCredentialRequest is sent to POST /credentials/:plugin/:key.
type SetCredentialRequest struct {
	Value string `json:"value"`
}

// SetCredentialResponse is returned by POST /credentials/:plugin/:key.
type SetCredentialResponse struct {
	Plugin string `json:"plugin"`
	Key    string `json:"key"`
	Set    bool   `json:"set"`
}

// ── Header Sets ──────────────────────────────────────────────────────────────

// CreateHeaderSetRequest is sent to POST /header-sets.
// Headers is an optional map of header name -> value to set immediately.
type CreateHeaderSetRequest struct {
	Name          string            `json:"name"`
	MatchPatterns []string          `json:"match_patterns"`
	Weight        int               `json:"weight,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// CreateHeaderSetResponse is returned by POST /header-sets.
type CreateHeaderSetResponse struct {
	Name    string `json:"name"`
	Created bool   `json:"created"`
}

// UpdateHeaderSetRequest is sent to PATCH /header-sets/:name.
// At least one field must be set.
type UpdateHeaderSetRequest struct {
	MatchPatterns *[]string `json:"match_patterns,omitempty"`
	Weight        *int      `json:"weight,omitempty"`
}

// HeaderSetListItem is one entry in the header-sets list. Headers contains
// only the header names (no values are exposed).
type HeaderSetListItem struct {
	Name          string   `json:"name"`
	MatchPatterns []string `json:"match_patterns"`
	Weight        int      `json:"weight"`
	Headers       []string `json:"headers"`
}

// HeaderSetListResponse is returned by GET /header-sets.
type HeaderSetListResponse struct {
	HeaderSets []HeaderSetListItem `json:"header_sets"`
}

// SetHeaderRequest is sent to POST /header-sets/:name/headers.
type SetHeaderRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SetHeaderResponse is returned by POST /header-sets/:name/headers.
type SetHeaderResponse struct {
	HeaderSet string `json:"header_set"`
	Header    string `json:"header"`
	Set       bool   `json:"set"`
}

// DeleteHeaderResponse is returned by DELETE /header-sets/:name/headers/:header_name.
type DeleteHeaderResponse struct {
	HeaderSet string `json:"header_set"`
	Header    string `json:"header"`
	Deleted   bool   `json:"deleted"`
}

// UpdateHeaderSetResponse is returned by PATCH /header-sets/:name.
type UpdateHeaderSetResponse struct {
	Name    string `json:"name"`
	Updated bool   `json:"updated"`
}

// DeleteHeaderSetResponse is returned by DELETE /header-sets/:name.
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
	PluginName     *string   `json:"plugin_name,omitempty"`
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
	Plugin    *string `json:"plugin,omitempty"`
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
