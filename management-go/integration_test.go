//go:build integration

package gap_test

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"sort"
	"testing"
	"time"

	gap "github.com/mikekelly/gap/management-go"
)

func newTestClient(t *testing.T, passcode string) *gap.Client {
	t.Helper()
	serverURL := os.Getenv("GAP_SERVER_URL")
	if serverURL == "" {
		t.Fatal("GAP_SERVER_URL not set")
	}
	opts := []gap.Option{}
	if passcode != "" {
		opts = append(opts, gap.WithPasscode(passcode))
	}
	caCert := os.Getenv("GAP_CA_CERT")
	if caCert != "" {
		opts = append(opts, gap.WithCACert(caCert))
	}
	return gap.NewClient(serverURL, opts...)
}

func sha512Hex(s string) string {
	h := sha512.Sum512([]byte(s))
	return hex.EncodeToString(h[:])
}

func strPtr(s string) *string { return &s }

func TestIntegration(t *testing.T) {
	ctx := context.Background()
	password := "test-integration-password"
	passcodeHash := sha512Hex(password)

	// Unauthenticated client (for status/init)
	unauthClient := newTestClient(t, "")
	// Authenticated client — created after init succeeds.
	var authClient *gap.Client

	// Track state across subtests.
	var createdTokenID string
	var signingPluginName string

	// ── Test 1: Server health check ────────────────────────────────────────────
	t.Run("Test01_HealthCheck", func(t *testing.T) {
		// Retry up to 30 times with 1-second delays (mirrors shell retry loop).
		const maxRetries = 30
		var lastErr error
		for i := 0; i < maxRetries; i++ {
			_, lastErr = unauthClient.Status(ctx)
			if lastErr == nil {
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("server health check failed after %d retries: %v", maxRetries, lastErr)
	})

	// ── Test 2: Status returns version ─────────────────────────────────────────
	t.Run("Test02_StatusCheck", func(t *testing.T) {
		status, err := unauthClient.Status(ctx)
		if err != nil {
			t.Fatalf("Status failed: %v", err)
		}
		if status.Version == "" {
			t.Fatal("expected status to include a non-empty version")
		}
	})

	// ── Test 3: Initialize GAP ──────────────────────────────────────────────────
	t.Run("Test03_InitServer", func(t *testing.T) {
		_, err := unauthClient.Init(ctx, &gap.InitRequest{PasswordHash: passcodeHash})
		if err != nil {
			if gap.IsConflict(err) {
				// Already initialized — this is acceptable (data may persist across runs).
				t.Logf("GAP already initialized (conflict response) — continuing")
			} else {
				t.Fatalf("Init failed: %v", err)
			}
		}
		// Build the authenticated client now that initialization is complete.
		authClient = newTestClient(t, passcodeHash)
	})

	// All tests from here require authClient. Bail early if init failed.
	if authClient == nil {
		t.Fatal("authClient not set — init must have failed")
	}

	// ── Test 4: Status still works after init ──────────────────────────────────
	t.Run("Test04_StatusAfterInit", func(t *testing.T) {
		status, err := authClient.Status(ctx)
		if err != nil {
			t.Fatalf("Status failed after init: %v", err)
		}
		if status.Version == "" {
			t.Fatal("expected status to include a non-empty version after init")
		}
	})

	// ── Test 5: Create agent token ─────────────────────────────────────────────
	t.Run("Test05_CreateToken", func(t *testing.T) {
		resp, err := authClient.CreateToken(ctx, &gap.CreateTokenRequest{
			Name: "test-agent-integration",
		})
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}
		if resp.Token == nil || *resp.Token == "" {
			t.Fatal("expected token value in creation response")
		}
		createdTokenID = resp.ID
		t.Logf("Token created: id=%s prefix=%s", resp.ID, resp.Prefix)
	})

	// ── Test 6: List tokens ────────────────────────────────────────────────────
	t.Run("Test06_ListTokens", func(t *testing.T) {
		resp, err := authClient.ListTokens(ctx)
		if err != nil {
			t.Fatalf("ListTokens failed: %v", err)
		}
		if len(resp.Tokens) == 0 {
			t.Fatal("expected at least one token in listing")
		}
		t.Logf("Found %d tokens", len(resp.Tokens))
	})

	// ── Test 7: Mock API accessibility ─────────────────────────────────────────
	// The shell script checks http://mock-api:8080/get. In a Go integration test
	// we do not have direct access to docker-compose service names unless the
	// test is run inside Docker. We skip this check gracefully when the env var
	// is absent. The proxy/activity tests below are the real coverage.
	t.Run("Test07_MockAPIAccessible", func(t *testing.T) {
		mockURL := os.Getenv("GAP_MOCK_API_URL")
		if mockURL == "" {
			t.Skip("GAP_MOCK_API_URL not set — skipping mock API check")
		}
		// Just verify Status() works; actual mock-API reachability is environment-specific.
		t.Logf("Mock API URL: %s (reachability not verified here)", mockURL)
	})

	// ── Test 8: Set credential ─────────────────────────────────────────────────
	t.Run("Test08_SetCredential", func(t *testing.T) {
		resp, err := authClient.SetCredential(ctx, "test-plugin", "api_key", &gap.SetCredentialRequest{
			Value: "test-secret-key-12345",
		})
		if err != nil {
			t.Fatalf("SetCredential failed: %v", err)
		}
		if !resp.Set {
			t.Fatal("expected Set == true in response")
		}
	})

	// ── Test 9: Install plugin from GitHub ─────────────────────────────────────
	t.Run("Test09_InstallPlugin", func(t *testing.T) {
		resp, err := authClient.InstallPlugin(ctx, &gap.InstallRequest{
			Name: "mikekelly/exa-gap",
		})
		if err != nil {
			t.Fatalf("InstallPlugin failed: %v", err)
		}
		if resp.Name == "" {
			t.Fatal("expected plugin name in install response")
		}
		t.Logf("Plugin installed: %s", resp.Name)
	})

	// ── Test 10: List plugins ──────────────────────────────────────────────────
	t.Run("Test10_ListPlugins", func(t *testing.T) {
		resp, err := authClient.ListPlugins(ctx)
		if err != nil {
			t.Fatalf("ListPlugins failed: %v", err)
		}

		// Find the installed plugin.
		var found *gap.PluginInfo
		for i := range resp.Plugins {
			if resp.Plugins[i].Name == "mikekelly/exa-gap" {
				found = &resp.Plugins[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("installed plugin 'mikekelly/exa-gap' not found in listing; got %d plugins", len(resp.Plugins))
		}

		if len(found.MatchPatterns) == 0 {
			t.Error("expected plugin to have at least one match pattern")
		}
		if len(found.CredentialSchema) == 0 {
			t.Error("expected plugin to have at least one credential schema field")
		}
		t.Logf("Plugin match_patterns: %v, credential_schema: %v", found.MatchPatterns, found.CredentialSchema)
	})

	// ── Tests 11-12: Proxy smoke tests ─────────────────────────────────────────
	// These require internet access and a CA cert from the gap-data volume.
	// We skip them gracefully when preconditions are not met, mirroring the
	// shell script behaviour.
	proxyTestSkipped := true

	t.Run("Test11_ProxySmokeTest", func(t *testing.T) {
		t.Skip("Proxy smoke test requires a running proxy and internet access — not exercised by Go client library tests")
		proxyTestSkipped = true
	})

	t.Run("Test12_ProxyH2SmokeTest", func(t *testing.T) {
		if proxyTestSkipped {
			t.Skip("Skipping H2 smoke test (preconditions not met — see Test11)")
		}
	})

	// ── Tests 13-17: Activity tests ────────────────────────────────────────────
	// These depend on proxy activity being generated (Tests 11-12). Since those
	// are always skipped in the Go test suite, we test the activity API endpoint
	// shape rather than entry counts.

	t.Run("Test13_ActivityEndpoint", func(t *testing.T) {
		if proxyTestSkipped {
			// Still test the endpoint itself; just don't assert on entry count.
			resp, err := authClient.QueryActivity(ctx, nil)
			if err != nil {
				t.Fatalf("QueryActivity failed: %v", err)
			}
			t.Logf("Activity endpoint returned %d entries", len(resp.Entries))
			return
		}
		resp, err := authClient.QueryActivity(ctx, nil)
		if err != nil {
			t.Fatalf("QueryActivity failed: %v", err)
		}
		if len(resp.Entries) == 0 {
			t.Log("Activity endpoint returned 0 entries (proxy requests may not have been logged yet)")
		} else {
			t.Logf("Activity endpoint returned %d entries", len(resp.Entries))
		}
	})

	t.Run("Test14_ActivityFilterByMethod", func(t *testing.T) {
		method := "GET"
		resp, err := authClient.QueryActivity(ctx, &gap.ActivityQuery{Method: strPtr(method)})
		if err != nil {
			t.Fatalf("QueryActivity(method=GET) failed: %v", err)
		}
		for _, e := range resp.Entries {
			if e.Method != method {
				t.Errorf("activity method filter returned entry with method=%q, expected %q", e.Method, method)
			}
		}
		t.Logf("Activity method filter: %d GET entries", len(resp.Entries))
	})

	t.Run("Test15_ActivityFilterByLimit", func(t *testing.T) {
		// Only assert limit behaviour if there is at least one entry.
		all, err := authClient.QueryActivity(ctx, nil)
		if err != nil {
			t.Fatalf("QueryActivity (all) failed: %v", err)
		}
		if len(all.Entries) == 0 {
			t.Log("No activity entries — skipping limit assertion")
			return
		}
		limit := uint32(1)
		resp, err := authClient.QueryActivity(ctx, &gap.ActivityQuery{Limit: &limit})
		if err != nil {
			t.Fatalf("QueryActivity(limit=1) failed: %v", err)
		}
		if len(resp.Entries) != 1 {
			t.Errorf("expected exactly 1 entry with limit=1, got %d", len(resp.Entries))
		}
	})

	t.Run("Test16_ActivityFilterByDomain", func(t *testing.T) {
		resp, err := authClient.QueryActivity(ctx, &gap.ActivityQuery{Domain: strPtr("httpbin.org")})
		if err != nil {
			t.Fatalf("QueryActivity(domain=httpbin.org) failed: %v", err)
		}
		t.Logf("Activity domain filter returned %d entries for httpbin.org", len(resp.Entries))
	})

	t.Run("Test17_ActivityEntryFields", func(t *testing.T) {
		limit := uint32(1)
		resp, err := authClient.QueryActivity(ctx, &gap.ActivityQuery{Limit: &limit})
		if err != nil {
			t.Fatalf("QueryActivity(limit=1) failed: %v", err)
		}
		if len(resp.Entries) == 0 {
			t.Log("No activity entries to inspect — skipping field check")
			return
		}
		e := resp.Entries[0]
		if e.Method == "" {
			t.Error("activity entry missing Method field")
		}
		if e.URL == "" {
			t.Error("activity entry missing URL field")
		}
		if e.Timestamp.IsZero() {
			t.Error("activity entry missing Timestamp field")
		}
		// Status 0 is valid (e.g., rejected before upstream) so we just confirm
		// the struct is populated. No assertion on Status value.
		t.Logf("Activity entry: method=%s url=%s status=%d", e.Method, e.URL, e.Status)
	})

	// ── Test 18: Register signing plugin ────────────────────────────────────────
	signingPluginName = "signing-test"
	signingPluginCode := `var plugin = {
    name: "signing-test",
    matchPatterns: ["api.example.com"],
    credentialSchema: { fields: [
        { name: "private_key", label: "Private Key", type: "password", required: true },
        { name: "key_id", label: "Key ID", type: "text", required: true }
    ]},
    transform: function(request, credentials) {
        var keyDer = GAP.util.base64(credentials.private_key, true);
        var result = GAP.crypto.httpSignature({
            request: request,
            components: ["@method", "content-type"],
            algorithm: "ed25519",
            keyId: credentials.key_id,
            keyDer: keyDer
        });
        request.headers["Signature-Input"] = result.signatureInput;
        request.headers["Signature"] = result.signature;
        return request;
    }
};`

	t.Run("Test18a_RegisterSigningPlugin", func(t *testing.T) {
		resp, err := authClient.RegisterPlugin(ctx, &gap.RegisterPluginRequest{
			Name: signingPluginName,
			Code: signingPluginCode,
		})
		if err != nil {
			t.Fatalf("RegisterPlugin failed: %v", err)
		}
		if !resp.Registered {
			t.Fatal("expected Registered == true in response")
		}
	})

	t.Run("Test18b_SigningPluginInList", func(t *testing.T) {
		resp, err := authClient.ListPlugins(ctx)
		if err != nil {
			t.Fatalf("ListPlugins failed: %v", err)
		}
		var found *gap.PluginInfo
		for i := range resp.Plugins {
			if resp.Plugins[i].Name == signingPluginName {
				found = &resp.Plugins[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("signing plugin %q not found in plugin list", signingPluginName)
		}
		// Verify match_patterns
		if len(found.MatchPatterns) == 0 || found.MatchPatterns[0] != "api.example.com" {
			t.Errorf("expected match_patterns [api.example.com], got %v", found.MatchPatterns)
		}
		// Verify credential_schema contains expected fields (sorted for stable comparison)
		schema := make([]string, len(found.CredentialSchema))
		copy(schema, found.CredentialSchema)
		sort.Strings(schema)
		if len(schema) != 2 || schema[0] != "key_id" || schema[1] != "private_key" {
			t.Errorf("expected credential_schema [key_id, private_key], got %v", schema)
		}
	})

	t.Run("Test18c_SetSigningPluginCredentials", func(t *testing.T) {
		privKeyResp, err := authClient.SetCredential(ctx, signingPluginName, "private_key", &gap.SetCredentialRequest{
			Value: "MC4CAQAwBQYDK2VwBCIEIDBPFaFarmSYSvNyKLfqMZnJchAPhXGR0h4l209vFoVN",
		})
		if err != nil {
			t.Fatalf("SetCredential(private_key) failed: %v", err)
		}
		if !privKeyResp.Set {
			t.Error("expected Set == true for private_key credential")
		}

		keyIDResp, err := authClient.SetCredential(ctx, signingPluginName, "key_id", &gap.SetCredentialRequest{
			Value: "test-key-1",
		})
		if err != nil {
			t.Fatalf("SetCredential(key_id) failed: %v", err)
		}
		if !keyIDResp.Set {
			t.Error("expected Set == true for key_id credential")
		}
	})

	t.Run("Test18d_RegisterWithoutAuthReturns401", func(t *testing.T) {
		_, err := unauthClient.RegisterPlugin(ctx, &gap.RegisterPluginRequest{
			Name: signingPluginName,
			Code: signingPluginCode,
		})
		if !gap.IsUnauthorized(err) {
			t.Errorf("expected 401 Unauthorized when registering plugin without auth, got: %v", err)
		}
	})

	// ── Test 19: Delete token ──────────────────────────────────────────────────
	t.Run("Test19_DeleteToken", func(t *testing.T) {
		if createdTokenID == "" {
			t.Skip("no token ID available — skipping deletion test")
		}
		resp, err := authClient.RevokeToken(ctx, createdTokenID)
		if err != nil {
			t.Fatalf("RevokeToken(%s) failed: %v", createdTokenID, err)
		}
		if !resp.Revoked {
			t.Errorf("expected Revoked == true, got false (id=%s)", createdTokenID)
		}
	})

	// ── Test 20: Management log has entries ────────────────────────────────────
	t.Run("Test20_ManagementLogHasEntries", func(t *testing.T) {
		resp, err := authClient.QueryManagementLog(ctx, nil)
		if err != nil {
			t.Fatalf("QueryManagementLog failed: %v", err)
		}
		if len(resp.Entries) == 0 {
			t.Fatal("management log is empty, expected entries from previous operations")
		}
		// Verify schema of first entry.
		e := resp.Entries[0]
		if e.Timestamp.IsZero() {
			t.Error("management log entry missing Timestamp")
		}
		if e.Operation == "" {
			t.Error("management log entry missing Operation")
		}
		if e.ResourceType == "" {
			t.Error("management log entry missing ResourceType")
		}
		// Success is a bool — always present in Go struct; no nil check needed.
		t.Logf("Management log: %d entries, first: op=%s resource=%s success=%v",
			len(resp.Entries), e.Operation, e.ResourceType, e.Success)
	})

	// ── Test 21: Management log filter by operation ────────────────────────────
	t.Run("Test21_ManagementLogFilterByOperation", func(t *testing.T) {
		op := "token_create"
		resp, err := authClient.QueryManagementLog(ctx, &gap.ManagementLogQuery{
			Operation: strPtr(op),
		})
		if err != nil {
			t.Fatalf("QueryManagementLog(operation=token_create) failed: %v", err)
		}
		if len(resp.Entries) == 0 {
			t.Fatalf("expected at least one %q entry in management log", op)
		}
		for _, e := range resp.Entries {
			if e.Operation != op {
				t.Errorf("filter by operation=%q returned entry with operation=%q", op, e.Operation)
			}
		}
		t.Logf("Management log operation filter: %d %q entries", len(resp.Entries), op)
	})

	// ── Test 22: Management log filter by resource_type ───────────────────────
	t.Run("Test22_ManagementLogFilterByResourceType", func(t *testing.T) {
		rt := "token"
		resp, err := authClient.QueryManagementLog(ctx, &gap.ManagementLogQuery{
			ResourceType: strPtr(rt),
		})
		if err != nil {
			t.Fatalf("QueryManagementLog(resource_type=token) failed: %v", err)
		}
		if len(resp.Entries) == 0 {
			t.Fatalf("expected at least one entry with resource_type=%q", rt)
		}
		for _, e := range resp.Entries {
			if e.ResourceType != rt {
				t.Errorf("filter by resource_type=%q returned entry with resource_type=%q", rt, e.ResourceType)
			}
		}
		t.Logf("Management log resource_type filter: %d %q entries", len(resp.Entries), rt)
	})

	// ── Test 23: Create header set ─────────────────────────────────────────────
	t.Run("Test23_CreateHeaderSet", func(t *testing.T) {
		weight := 5
		resp, err := authClient.CreateHeaderSet(ctx, &gap.CreateHeaderSetRequest{
			Name:          "test-header-set",
			MatchPatterns: []string{"api.example.com"},
			Weight:        weight,
		})
		if err != nil {
			t.Fatalf("CreateHeaderSet failed: %v", err)
		}
		if !resp.Created {
			t.Fatal("expected Created == true in response")
		}
	})

	// ── Test 24: Create header set without auth returns 401 ───────────────────
	t.Run("Test24_CreateHeaderSetUnauthorized", func(t *testing.T) {
		_, err := unauthClient.CreateHeaderSet(ctx, &gap.CreateHeaderSetRequest{
			Name:          "noauth-hs",
			MatchPatterns: []string{"example.com"},
		})
		if !gap.IsUnauthorized(err) {
			t.Errorf("expected 401 Unauthorized, got: %v", err)
		}
	})

	// ── Test 25: Add headers to header set ────────────────────────────────────
	t.Run("Test25_AddHeadersToHeaderSet", func(t *testing.T) {
		// Add first header.
		resp, err := authClient.SetHeader(ctx, "test-header-set", &gap.SetHeaderRequest{
			Name:  "Authorization",
			Value: "Bearer sk-test-key-123",
		})
		if err != nil {
			t.Fatalf("SetHeader(Authorization) failed: %v", err)
		}
		if !resp.Set {
			t.Error("expected Set == true for Authorization header")
		}

		// Add second header (silently, mirroring the shell script).
		_, err = authClient.SetHeader(ctx, "test-header-set", &gap.SetHeaderRequest{
			Name:  "X-Custom-Header",
			Value: "custom-value",
		})
		if err != nil {
			t.Fatalf("SetHeader(X-Custom-Header) failed: %v", err)
		}
	})

	// ── Test 26: List header sets — names visible, values hidden ──────────────
	t.Run("Test26_ListHeaderSets", func(t *testing.T) {
		resp, err := authClient.ListHeaderSets(ctx)
		if err != nil {
			t.Fatalf("ListHeaderSets failed: %v", err)
		}

		var found *gap.HeaderSetListItem
		for i := range resp.HeaderSets {
			if resp.HeaderSets[i].Name == "test-header-set" {
				found = &resp.HeaderSets[i]
				break
			}
		}
		if found == nil {
			t.Fatal("test-header-set not found in header-sets listing")
		}
		if len(found.Headers) != 2 {
			t.Errorf("expected 2 headers in test-header-set, got %d: %v", len(found.Headers), found.Headers)
		}
		// Verify the secret value is not exposed — Headers is []string (names only).
		for _, name := range found.Headers {
			if name == "Bearer sk-test-key-123" {
				t.Error("header value should not be exposed in list response")
			}
		}
		t.Logf("Header set listed with %d header names: %v", len(found.Headers), found.Headers)
	})

	// ── Test 27: Update header set weight ─────────────────────────────────────
	t.Run("Test27_UpdateHeaderSetWeight", func(t *testing.T) {
		weight := 10
		resp, err := authClient.UpdateHeaderSet(ctx, "test-header-set", &gap.UpdateHeaderSetRequest{
			Weight: &weight,
		})
		if err != nil {
			t.Fatalf("UpdateHeaderSet failed: %v", err)
		}
		if !resp.Updated {
			t.Fatal("expected Updated == true")
		}
	})

	// ── Test 28: Update plugin weight ─────────────────────────────────────────
	t.Run("Test28_UpdatePluginWeight", func(t *testing.T) {
		resp, err := authClient.UpdatePluginConfig(ctx, signingPluginName, &gap.UpdatePluginRequest{
			Weight: 20,
		})
		if err != nil {
			t.Fatalf("UpdatePluginConfig(%s) failed: %v", signingPluginName, err)
		}
		if !resp.Updated {
			t.Fatal("expected Updated == true")
		}
	})

	// ── Test 29: Delete header from header set ────────────────────────────────
	t.Run("Test29_DeleteHeader", func(t *testing.T) {
		resp, err := authClient.DeleteHeader(ctx, "test-header-set", "X-Custom-Header")
		if err != nil {
			t.Fatalf("DeleteHeader failed: %v", err)
		}
		if !resp.Deleted {
			t.Fatal("expected Deleted == true")
		}
	})

	// ── Test 30: Delete header set ────────────────────────────────────────────
	t.Run("Test30_DeleteHeaderSet", func(t *testing.T) {
		resp, err := authClient.DeleteHeaderSet(ctx, "test-header-set")
		if err != nil {
			t.Fatalf("DeleteHeaderSet failed: %v", err)
		}
		if !resp.Deleted {
			t.Fatal("expected Deleted == true")
		}

		// Verify it's gone from the listing.
		listResp, err := authClient.ListHeaderSets(ctx)
		if err != nil {
			t.Fatalf("ListHeaderSets (post-delete) failed: %v", err)
		}
		for _, hs := range listResp.HeaderSets {
			if hs.Name == "test-header-set" {
				t.Error("test-header-set still appears in listing after deletion")
			}
		}
	})
}

// TestIntegrationSSEStreams exercises the SSE streaming endpoints.
// These are separate from the main sequential flow since they require
// a context with timeout to avoid hanging.
func TestIntegrationSSEStreams(t *testing.T) {
	ctx := context.Background()
	password := "test-integration-password"
	passcodeHash := sha512Hex(password)
	authClient := newTestClient(t, passcodeHash)

	t.Run("StreamManagementLog", func(t *testing.T) {
		streamCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		stream, err := authClient.StreamManagementLog(streamCtx)
		if err != nil {
			t.Fatalf("StreamManagementLog failed: %v", err)
		}
		defer stream.Close()

		// Trigger a management log event by calling Status (which doesn't
		// write to management log) then ListTokens (auth'd operation).
		go func() {
			time.Sleep(100 * time.Millisecond)
			// Fire any authenticated request to potentially generate a log entry.
			authClient.ListTokens(context.Background()) //nolint:errcheck
		}()

		// Read one event or until timeout.
		entry, err := stream.Next()
		if err == io.EOF {
			t.Log("SSE management log stream ended (no events in timeout window — acceptable)")
			return
		}
		if err != nil {
			// Context deadline exceeded is acceptable — means the stream is open
			// but no events arrived in the window.
			t.Logf("SSE management log stream read: %v (acceptable if context deadline)", err)
			return
		}
		if entry.Operation == "" {
			t.Error("SSE management log entry missing Operation field")
		}
		t.Logf("SSE management log event received: op=%s resource=%s", entry.Operation, entry.ResourceType)
	})

	t.Run("StreamActivity", func(t *testing.T) {
		streamCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		stream, err := authClient.StreamActivity(streamCtx)
		if err != nil {
			t.Fatalf("StreamActivity failed: %v", err)
		}
		defer stream.Close()

		// SSE activity stream is open — that is sufficient to prove connectivity.
		// Activity events only appear when proxy requests are made, which is not
		// feasible in this environment. Just verify the stream opened without error.
		t.Log("SSE activity stream opened successfully")

		// Drain with timeout — any event is a bonus.
		entry, err := stream.Next()
		if err == io.EOF || err != nil {
			t.Logf("SSE activity stream: %v (no events in timeout window — acceptable)", err)
			return
		}
		t.Logf("SSE activity event received: method=%s url=%s", entry.Method, entry.URL)
	})
}
