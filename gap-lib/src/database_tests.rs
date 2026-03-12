    use super::*;
    use chrono::Duration;
    use sha2::Digest;

    // ── Token CRUD ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_token_add_and_get() {
        let db = GapDatabase::in_memory().await.unwrap();
        let now = Utc::now();

        // Token without scopes (unrestricted)
        db.add_token("gap_abc123def456", now, None, "default", "default").await.unwrap();

        let meta = db.get_token("gap_abc123def456", "default", "default").await.unwrap().unwrap();
        assert!(meta.scopes.is_none());
        assert!(meta.revoked_at.is_none());
        // Round-trip via RFC 3339 may lose sub-microsecond precision;
        // compare to the second.
        assert_eq!(meta.created_at.timestamp(), now.timestamp());
    }

    #[tokio::test]
    async fn test_token_add_with_scopes() {
        let db = GapDatabase::in_memory().await.unwrap();
        let now = Utc::now();

        let scopes = vec![
            TokenScope {
                host_pattern: "example.com".to_string(),
                port: None,
                path_pattern: "/*".to_string(),
                methods: None,
            },
            TokenScope {
                host_pattern: "api.test.com".to_string(),
                port: Some(8080),
                path_pattern: "/v1/*".to_string(),
                methods: Some(vec!["GET".to_string(), "POST".to_string()]),
            },
        ];

        db.add_token("gap_scoped_token1", now, Some(&scopes), "default", "default")
            .await
            .unwrap();

        let meta = db.get_token("gap_scoped_token1", "default", "default").await.unwrap().unwrap();
        let retrieved_scopes = meta.scopes.unwrap();
        assert_eq!(retrieved_scopes.len(), 2);
        assert_eq!(retrieved_scopes[0].host_pattern, "example.com");
        assert_eq!(retrieved_scopes[1].port, Some(8080));
        assert_eq!(
            retrieved_scopes[1].methods,
            Some(vec!["GET".to_string(), "POST".to_string()])
        );
    }

    #[tokio::test]
    async fn test_token_add_with_empty_scopes() {
        let db = GapDatabase::in_memory().await.unwrap();
        let now = Utc::now();

        // Empty scopes = deny all (different from None = unrestricted)
        db.add_token("gap_empty_scopes1", now, Some(&[]), "default", "default")
            .await
            .unwrap();

        let meta = db.get_token("gap_empty_scopes1", "default", "default").await.unwrap().unwrap();
        assert_eq!(meta.scopes, Some(vec![])); // Some(empty) not None
    }

    #[tokio::test]
    async fn test_token_get_nonexistent() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert!(db.get_token("nope", "default", "default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_token_list() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert_eq!(db.list_tokens(false, "default", "default").await.unwrap().len(), 0);

        let now = Utc::now();
        db.add_token("gap_t1_abcdef01", now, None, "default", "default").await.unwrap();
        db.add_token("gap_t2_abcdef02", now, None, "default", "default").await.unwrap();

        let tokens = db.list_tokens(false, "default", "default").await.unwrap();
        assert_eq!(tokens.len(), 2);
    }

    #[tokio::test]
    async fn test_token_revoke() {
        let db = GapDatabase::in_memory().await.unwrap();
        let now = Utc::now();

        db.add_token("gap_t1_revoke01", now, None, "default", "default").await.unwrap();
        db.add_token("gap_t2_revoke02", now, None, "default", "default").await.unwrap();

        db.revoke_token("gap_t1_revoke01", "default", "default").await.unwrap();

        // Not in active list
        let tokens = db.list_tokens(false, "default", "default").await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_value, "gap_t2_revoke02");

        // In full list with revoked_at set
        let all_tokens = db.list_tokens(true, "default", "default").await.unwrap();
        assert_eq!(all_tokens.len(), 2);
        let revoked = all_tokens
            .iter()
            .find(|t| t.token_value == "gap_t1_revoke01")
            .unwrap();
        assert!(revoked.revoked_at.is_some());

        // get_token returns None for revoked
        assert!(db.get_token("gap_t1_revoke01", "default", "default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_token_get_by_prefix() {
        let db = GapDatabase::in_memory().await.unwrap();
        let now = Utc::now();

        db.add_token("gap_abc123def456", now, None, "default", "default").await.unwrap();

        let found = db.get_token_by_prefix("gap_abc123de", "default", "default").await.unwrap();
        assert_eq!(found, Some("gap_abc123def456".to_string()));

        let not_found = db.get_token_by_prefix("gap_zzz", "default", "default").await.unwrap();
        assert!(not_found.is_none());
    }

    // ── Plugin CRUD ─────────────────────────────────────────────────

    fn sample_plugin(id: &str) -> PluginEntry {
        PluginEntry {
            id: id.to_string(),
            source: None,
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        }
    }

    #[tokio::test]
    async fn test_plugin_add_and_get() {
        let db = GapDatabase::in_memory().await.unwrap();
        let plugin = sample_plugin("placeholder");

        let id = db.add_plugin(&plugin, "function transform() {}", "default", "default").await.unwrap();

        let got = db.get_plugin(&id, "default", "default").await.unwrap().unwrap();
        assert_eq!(got.id, id);
        assert_eq!(got.hosts, vec!["api.example.com"]);
        assert_eq!(got.credential_schema, vec!["api_key"]);
        assert!(got.source.is_none());
    }

    #[tokio::test]
    async fn test_plugin_get_source() {
        let db = GapDatabase::in_memory().await.unwrap();
        let plugin = sample_plugin("placeholder");

        let id = db.add_plugin(&plugin, "// source code here", "default", "default")
            .await
            .unwrap();

        let src = db.get_plugin_source(&id, "default", "default").await.unwrap().unwrap();
        assert_eq!(src, "// source code here");
    }

    #[tokio::test]
    async fn test_plugin_get_nonexistent() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert!(db.get_plugin("nonexistent-id", "default", "default").await.unwrap().is_none());
        assert!(db.get_plugin_source("nonexistent-id", "default", "default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_plugin_list() {
        let db = GapDatabase::in_memory().await.unwrap();

        assert_eq!(db.list_plugins("default", "default").await.unwrap().len(), 0);

        db.add_plugin(&sample_plugin("placeholder1"), "src1", "default", "default").await.unwrap();
        db.add_plugin(&sample_plugin("placeholder2"), "src2", "default", "default")
            .await
            .unwrap();

        let plugins = db.list_plugins("default", "default").await.unwrap();
        assert_eq!(plugins.len(), 2);
    }

    #[tokio::test]
    async fn test_plugin_remove_preserves_credentials() {
        let db = GapDatabase::in_memory().await.unwrap();

        let id = db.add_plugin(&sample_plugin("placeholder"), "src", "default", "default").await.unwrap();
        db.set_credential(&id, "api_key", "secret", "default", "default")
            .await
            .unwrap();

        // Remove plugin
        db.remove_plugin(&id, "default", "default").await.unwrap();

        // Plugin is gone
        assert!(db.get_plugin(&id, "default", "default").await.unwrap().is_none());
        // Credentials are preserved
        let cred = db.get_credential(&id, "api_key", "default", "default").await.unwrap();
        assert_eq!(cred, Some("secret".to_string()));
    }

    #[tokio::test]
    async fn test_plugin_has() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert!(!db.has_plugin("nonexistent-id", "default", "default").await.unwrap());

        let id = db.add_plugin(&sample_plugin("placeholder"), "src", "default", "default").await.unwrap();
        assert!(db.has_plugin(&id, "default", "default").await.unwrap());
    }

    #[tokio::test]
    async fn test_plugin_with_commit_sha() {
        let db = GapDatabase::in_memory().await.unwrap();
        let plugin = PluginEntry {
            id: "placeholder".to_string(),
            source: None,
            hosts: vec!["api.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: Some("abc1234".to_string()),
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };

        let id = db.add_plugin(&plugin, "src", "default", "default").await.unwrap();

        let got = db.get_plugin(&id, "default", "default").await.unwrap().unwrap();
        assert_eq!(got.commit_sha, Some("abc1234".to_string()));
    }

    // ── Credential CRUD ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_credential_set_and_get() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.set_credential("plugin-id-1", "api_key", "secret", "default", "default")
            .await
            .unwrap();

        let val = db.get_credential("plugin-id-1", "api_key", "default", "default").await.unwrap();
        assert_eq!(val, Some("secret".to_string()));
    }

    #[tokio::test]
    async fn test_credential_get_nonexistent() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert!(db.get_credential("nope", "nope", "default", "default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_credential_get_plugin_credentials() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.set_credential("plugin-id-1", "api_key", "key-val", "default", "default")
            .await
            .unwrap();
        db.set_credential("plugin-id-1", "secret", "secret-val", "default", "default")
            .await
            .unwrap();

        let creds = db.get_plugin_credentials("plugin-id-1", "default", "default").await.unwrap().unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds.get("api_key").unwrap(), "key-val");
        assert_eq!(creds.get("secret").unwrap(), "secret-val");

        // Nonexistent plugin returns None
        assert!(db.get_plugin_credentials("nope", "default", "default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_credential_list() {
        let db = GapDatabase::in_memory().await.unwrap();

        assert_eq!(db.list_credentials("default", "default").await.unwrap().len(), 0);

        db.set_credential("plugin-id-1", "api_key", "v1", "default", "default").await.unwrap();
        db.set_credential("plugin-id-2", "token", "v2", "default", "default").await.unwrap();

        let creds = db.list_credentials("default", "default").await.unwrap();
        assert_eq!(creds.len(), 2);
        assert!(creds.iter().any(|c| c.plugin_id == "plugin-id-1" && c.field == "api_key"));
        assert!(creds.iter().any(|c| c.plugin_id == "plugin-id-2" && c.field == "token"));
    }

    #[tokio::test]
    async fn test_credential_remove() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.set_credential("plugin-id-1", "api_key", "v1", "default", "default").await.unwrap();
        db.set_credential("plugin-id-1", "secret", "v2", "default", "default").await.unwrap();

        db.remove_credential("plugin-id-1", "api_key", "default", "default").await.unwrap();

        assert!(db.get_credential("plugin-id-1", "api_key", "default", "default").await.unwrap().is_none());
        assert_eq!(
            db.get_credential("plugin-id-1", "secret", "default", "default").await.unwrap(),
            Some("v2".to_string())
        );
    }

    // ── Config KV ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_config_set_get_delete() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Not found initially
        assert!(db.get_config("my_key").await.unwrap().is_none());

        // Set and get
        db.set_config("my_key", b"hello world").await.unwrap();
        let val = db.get_config("my_key").await.unwrap().unwrap();
        assert_eq!(val, b"hello world");

        // Overwrite
        db.set_config("my_key", b"updated").await.unwrap();
        let val = db.get_config("my_key").await.unwrap().unwrap();
        assert_eq!(val, b"updated");

        // Delete
        db.delete_config("my_key").await.unwrap();
        assert!(db.get_config("my_key").await.unwrap().is_none());
    }

    // ── Password Hash ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_password_hash() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Not initialized
        assert!(!db.is_initialized().await.unwrap());
        assert!(db.get_password_hash().await.unwrap().is_none());

        // Set hash
        db.set_password_hash("argon2$hash$here").await.unwrap();
        assert!(db.is_initialized().await.unwrap());
        assert_eq!(
            db.get_password_hash().await.unwrap(),
            Some("argon2$hash$here".to_string())
        );
    }

    // ── Activity ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_activity_log_and_get() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/users".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].method, "GET");
        assert_eq!(logs[0].url, "https://api.example.com/users");
        assert_eq!(logs[0].agent_id, Some("agent-1".to_string()));
        assert_eq!(logs[0].status, 200);
    }

    #[tokio::test]
    async fn test_activity_get_with_limit() {
        let db = GapDatabase::in_memory().await.unwrap();

        for i in 0..5 {
            let entry = ActivityEntry {
                timestamp: Utc::now() + Duration::seconds(i),
                request_id: None,
                method: "GET".to_string(),
                url: format!("https://api.example.com/{}", i),
                agent_id: None,
                status: 200,
                plugin_id: None,
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            };
            db.log_activity(&entry).await.unwrap();
        }

        let logs = db.get_activity(Some(3)).await.unwrap();
        assert_eq!(logs.len(), 3);
        // Newest first
        assert!(logs[0].url.contains("/4"));
    }

    #[tokio::test]
    async fn test_activity_get_since() {
        let db = GapDatabase::in_memory().await.unwrap();

        let past = Utc::now() - Duration::hours(2);
        let recent = Utc::now() - Duration::minutes(30);
        let now = Utc::now();

        // Old entry
        db.log_activity(&ActivityEntry {
            timestamp: past,
            request_id: None,
            method: "GET".to_string(),
            url: "https://old.example.com".to_string(),
            agent_id: None,
            status: 200,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        })
        .await
        .unwrap();

        // Recent entry
        db.log_activity(&ActivityEntry {
            timestamp: now,
            request_id: None,
            method: "POST".to_string(),
            url: "https://new.example.com".to_string(),
            agent_id: Some("agent-2".to_string()),
            status: 201,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        })
        .await
        .unwrap();

        let logs = db.get_activity_since(recent).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].method, "POST");
    }

    #[tokio::test]
    async fn test_activity_no_agent_id() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "DELETE".to_string(),
            url: "https://api.example.com/resource".to_string(),
            agent_id: None,
            status: 204,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].agent_id, None);
    }

    #[tokio::test]
    async fn test_activity_with_plugin_info() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_id: Some("exa".to_string()),
            plugin_sha: Some("abc1234".to_string()),
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].plugin_id, Some("exa".to_string()));
        assert_eq!(logs[0].plugin_sha, Some("abc1234".to_string()));
    }

    #[tokio::test]
    async fn test_activity_with_no_plugin_info() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: None,
            status: 200,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].plugin_id, None);
        assert_eq!(logs[0].plugin_sha, None);
    }

    #[tokio::test]
    async fn test_activity_with_source_hash() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_id: Some("exa".to_string()),
            plugin_sha: Some("abc1234".to_string()),
            source_hash: Some("deadbeef1234".to_string()),
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].source_hash, Some("deadbeef1234".to_string()));
    }

    #[tokio::test]
    async fn test_activity_with_request_headers() {
        let db = GapDatabase::in_memory().await.unwrap();

        let headers_json = r#"{"Authorization":"Bearer [REDACTED]","Host":"api.example.com"}"#;
        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_id: Some("exa".to_string()),
            plugin_sha: None,
            source_hash: None,
            request_headers: Some(headers_json.to_string()),
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0].request_headers,
            Some(headers_json.to_string())
        );
    }

    #[tokio::test]
    async fn test_activity_without_request_headers() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: None,
            status: 200,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].request_headers, None);
    }

    // ── Filtered Activity Queries ──────────────────────────────────

    /// Helper: seed diverse activity entries for query_activity tests
    async fn seed_activity(db: &GapDatabase) {
        let entries = vec![
            ActivityEntry {
                timestamp: Utc::now() - Duration::seconds(5),
                request_id: Some("aaa0000000000001".to_string()),
                method: "GET".to_string(),
                url: "https://api.example.com/users".to_string(),
                agent_id: Some("agent-1".to_string()),
                status: 200,
                plugin_id: Some("exa".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            },
            ActivityEntry {
                timestamp: Utc::now() - Duration::seconds(4),
                request_id: Some("aaa0000000000002".to_string()),
                method: "POST".to_string(),
                url: "https://api.example.com/data".to_string(),
                agent_id: Some("agent-1".to_string()),
                status: 201,
                plugin_id: Some("exa".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            },
            ActivityEntry {
                timestamp: Utc::now() - Duration::seconds(3),
                request_id: Some("bbb0000000000003".to_string()),
                method: "GET".to_string(),
                url: "https://other.service.io/health".to_string(),
                agent_id: Some("agent-2".to_string()),
                status: 200,
                plugin_id: Some("github".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            },
            ActivityEntry {
                timestamp: Utc::now() - Duration::seconds(2),
                request_id: Some("ccc0000000000004".to_string()),
                method: "DELETE".to_string(),
                url: "https://api.example.com/items/42".to_string(),
                agent_id: Some("agent-2".to_string()),
                status: 204,
                plugin_id: None,
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            },
        ];
        for entry in &entries {
            db.log_activity(entry).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_query_activity_empty_filter_returns_all() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter::default();
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 4);
        // Newest first (ORDER BY id DESC)
        assert_eq!(results[0].method, "DELETE");
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_domain() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            domain: Some("api.example.com".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 3); // 3 entries with api.example.com
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_plugin() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            plugin_id: Some("exa".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 2); // 2 entries with plugin_id "exa"
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_method() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            method: Some("GET".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 2); // 2 GET requests
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_agent() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            agent: Some("agent-2".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 2); // 2 entries from agent-2
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_request_id() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            request_id: Some("bbb0000000000003".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://other.service.io/health");
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_path() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            path: Some("/users".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://api.example.com/users");
    }

    #[tokio::test]
    async fn test_query_activity_combined_filters() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        // Filter by domain + method — should match only GET on api.example.com
        let filter = crate::types::ActivityFilter {
            domain: Some("api.example.com".to_string()),
            method: Some("GET".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://api.example.com/users");
    }

    #[tokio::test]
    async fn test_query_activity_with_limit() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            limit: Some(2),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_since() {
        let db = GapDatabase::in_memory().await.unwrap();

        let past = Utc::now() - Duration::hours(2);
        let recent = Utc::now() - Duration::minutes(5);

        // Old entry
        db.log_activity(&ActivityEntry {
            timestamp: past,
            request_id: None,
            method: "GET".to_string(),
            url: "https://old.example.com".to_string(),
            agent_id: None,
            status: 200,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        }).await.unwrap();

        // Recent entry
        db.log_activity(&ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "POST".to_string(),
            url: "https://new.example.com".to_string(),
            agent_id: None,
            status: 201,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        }).await.unwrap();

        let filter = crate::types::ActivityFilter {
            since: Some(recent),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, "POST");
    }

    #[tokio::test]
    async fn test_query_activity_request_id_stored_and_retrieved() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: Some("deadbeef12345678".to_string()),
            method: "GET".to_string(),
            url: "https://api.example.com/test".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].request_id, Some("deadbeef12345678".to_string()));
    }

    #[tokio::test]
    async fn test_query_activity_no_match_returns_empty() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            plugin_id: Some("nonexistent".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    // ── Plugin Version History ──────────────────────────────────────

    #[tokio::test]
    async fn test_add_plugin_and_get_by_hash() {
        let db = GapDatabase::in_memory().await.unwrap();

        let source_code = "function transform() {}";
        let source_hash = format!("{:x}", sha2::Sha256::digest(source_code.as_bytes()));

        let plugin = PluginEntry {
            id: "placeholder".to_string(),
            source: None,
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: Some("abc1234".to_string()),
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        let id = db.add_plugin(&plugin, source_code, "default", "default").await.unwrap();

        let version = db.get_plugin_version_by_hash(&source_hash, "default", "default").await.unwrap();
        assert!(version.is_some());
        let version = version.unwrap();
        assert_eq!(version.plugin_id, id);
        assert_eq!(version.commit_sha, Some("abc1234".to_string()));
        assert_eq!(version.source_hash, source_hash);
        assert_eq!(version.source_code, source_code);
    }

    #[tokio::test]
    async fn test_get_plugin_version_by_hash_not_found() {
        let db = GapDatabase::in_memory().await.unwrap();
        let result = db.get_plugin_version_by_hash("nonexistent", "default", "default").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_add_plugin_creates_version_entry() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin = sample_plugin("placeholder");
        let source_code = "function transform() { return request; }";
        let id = db.add_plugin(&plugin, source_code, "default", "default").await.unwrap();

        // Compute expected hash
        let expected_hash = format!("{:x}", sha2::Sha256::digest(source_code.as_bytes()));

        // Should be able to find the version by hash
        let version = db.get_plugin_version_by_hash(&expected_hash, "default", "default").await.unwrap();
        assert!(version.is_some());
        let version = version.unwrap();
        assert_eq!(version.plugin_id, id);
        assert_eq!(version.source_code, source_code);
    }

    #[tokio::test]
    async fn test_plugin_versions_are_append_only() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin = sample_plugin("placeholder");

        // Install v1
        let code_v1 = "// version 1";
        db.add_plugin(&plugin, code_v1, "default", "default").await.unwrap();

        // Install v2 (different code, gets a new UUID)
        let code_v2 = "// version 2";
        db.add_plugin(&plugin, code_v2, "default", "default").await.unwrap();

        // Both versions should exist
        let hash_v1 = format!("{:x}", sha2::Sha256::digest(code_v1.as_bytes()));
        let hash_v2 = format!("{:x}", sha2::Sha256::digest(code_v2.as_bytes()));

        let v1 = db.get_plugin_version_by_hash(&hash_v1, "default", "default").await.unwrap();
        let v2 = db.get_plugin_version_by_hash(&hash_v2, "default", "default").await.unwrap();
        assert!(v1.is_some());
        assert!(v2.is_some());
        assert_eq!(v1.unwrap().source_code, code_v1);
        assert_eq!(v2.unwrap().source_code, code_v2);
    }

    // ── Append-only tombstone behavior ─────────────────────────────

    #[tokio::test]
    async fn test_remove_plugin_creates_tombstone() {
        let db = GapDatabase::in_memory().await.unwrap();

        let id = db.add_plugin(&sample_plugin("placeholder"), "src", "default", "default").await.unwrap();
        db.remove_plugin(&id, "default", "default").await.unwrap();

        // Plugin should be invisible via get/has/list
        assert!(db.get_plugin(&id, "default", "default").await.unwrap().is_none());
        assert!(!db.has_plugin(&id, "default", "default").await.unwrap());
        assert_eq!(db.list_plugins("default", "default").await.unwrap().len(), 0);
        assert!(db.get_plugin_source(&id, "default", "default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_reinstall_after_delete() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Install, delete, reinstall
        let id1 = db.add_plugin(&sample_plugin("placeholder"), "v1 src", "default", "default").await.unwrap();
        db.remove_plugin(&id1, "default", "default").await.unwrap();
        assert!(db.get_plugin(&id1, "default", "default").await.unwrap().is_none());

        let id2 = db.add_plugin(&sample_plugin("placeholder"), "v2 src", "default", "default").await.unwrap();
        let got = db.get_plugin(&id2, "default", "default").await.unwrap().unwrap();
        assert_eq!(got.id, id2);

        let src = db.get_plugin_source(&id2, "default", "default").await.unwrap().unwrap();
        assert_eq!(src, "v2 src");
    }

    #[tokio::test]
    async fn test_list_plugins_only_latest_non_deleted() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Install two plugins
        let id1 = db.add_plugin(&sample_plugin("placeholder1"), "src1", "default", "default").await.unwrap();
        let id2 = db.add_plugin(&sample_plugin("placeholder2"), "src2", "default", "default").await.unwrap();

        // Delete one
        db.remove_plugin(&id1, "default", "default").await.unwrap();

        let plugins = db.list_plugins("default", "default").await.unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].id, id2);
    }

    #[tokio::test]
    async fn test_update_plugin_shows_latest_version() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin_v1 = PluginEntry {
            id: "placeholder".to_string(),
            source: None,
            hosts: vec!["api.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: Some("aaa1111".to_string()),
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        let id1 = db.add_plugin(&plugin_v1, "v1 code", "default", "default").await.unwrap();

        let plugin_v2 = PluginEntry {
            id: "placeholder".to_string(),
            source: None,
            hosts: vec!["api.exa.ai".to_string(), "new.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string(), "secret".to_string()],
            commit_sha: Some("bbb2222".to_string()),
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        let id2 = db.add_plugin(&plugin_v2, "v2 code", "default", "default").await.unwrap();

        // Each add_plugin generates a unique UUID, so both plugins exist independently
        let got1 = db.get_plugin(&id1, "default", "default").await.unwrap().unwrap();
        assert_eq!(got1.hosts, vec!["api.exa.ai"]);
        assert_eq!(got1.commit_sha, Some("aaa1111".to_string()));

        let got2 = db.get_plugin(&id2, "default", "default").await.unwrap().unwrap();
        assert_eq!(got2.hosts, vec!["api.exa.ai", "new.exa.ai"]);
        assert_eq!(got2.credential_schema, vec!["api_key", "secret"]);
        assert_eq!(got2.commit_sha, Some("bbb2222".to_string()));

        // get_plugin_source should return respective code
        let src2 = db.get_plugin_source(&id2, "default", "default").await.unwrap().unwrap();
        assert_eq!(src2, "v2 code");

        // list should show both plugins (each has a unique ID)
        let plugins = db.list_plugins("default", "default").await.unwrap();
        assert_eq!(plugins.len(), 2);
    }

    #[tokio::test]
    async fn test_dangerously_permit_http_stored_and_retrieved() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Plugin with dangerously_permit_http = true
        let plugin = PluginEntry {
            id: "placeholder".to_string(),
            source: None,
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: true,
            weight: 0,
            installed_at: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        let id = db.add_plugin(&plugin, "src", "default", "default").await.unwrap();

        let got = db.get_plugin(&id, "default", "default").await.unwrap().unwrap();
        assert!(got.dangerously_permit_http, "dangerously_permit_http should be true");
    }

    #[tokio::test]
    async fn test_dangerously_permit_http_defaults_false() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Plugin without dangerously_permit_http (default false)
        let plugin = sample_plugin("placeholder");
        let id = db.add_plugin(&plugin, "src", "default", "default").await.unwrap();

        let got = db.get_plugin(&id, "default", "default").await.unwrap().unwrap();
        assert!(!got.dangerously_permit_http, "dangerously_permit_http should default to false");
    }

    #[tokio::test]
    async fn test_dangerously_permit_http_in_list_plugins() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin = PluginEntry {
            id: "placeholder".to_string(),
            source: None,
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: true,
            weight: 0,
            installed_at: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.add_plugin(&plugin, "src", "default", "default").await.unwrap();

        let plugins = db.list_plugins("default", "default").await.unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(plugins[0].dangerously_permit_http);
    }

    // ── Rejection Tracking ─────────────────────────────────────────

    #[tokio::test]
    async fn test_activity_with_rejection() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: Some("rej001".to_string()),
            method: "GET".to_string(),
            url: "https://unknown.host.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 0,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: Some("no_matching_plugin".to_string()),
            rejection_reason: Some("Host 'unknown.host.com' has no matching plugin".to_string()),
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].status, 0);
        assert_eq!(logs[0].rejection_stage, Some("no_matching_plugin".to_string()));
        assert_eq!(logs[0].rejection_reason, Some("Host 'unknown.host.com' has no matching plugin".to_string()));
    }

    // ── Request Details ────────────────────────────────────────────

    #[tokio::test]
    async fn test_request_details_round_trip() {
        let db = GapDatabase::in_memory().await.unwrap();

        let details = crate::types::RequestDetails {
            request_id: "test-req-001".to_string(),
            req_headers: Some(r#"{"Host":"api.example.com","Accept":"*/*"}"#.to_string()),
            req_body: Some(b"request body here".to_vec()),
            transformed_url: Some("https://api.example.com/v2/data".to_string()),
            transformed_headers: Some(r#"{"Authorization":"Bearer [REDACTED]","Host":"api.example.com"}"#.to_string()),
            transformed_body: Some(b"transformed body".to_vec()),
            response_status: Some(200),
            response_headers: Some(r#"{"Content-Type":"application/json"}"#.to_string()),
            response_body: Some(b"{\"result\":\"ok\"}".to_vec()),
            body_truncated: false,
        };
        db.save_request_details(&details).await.unwrap();

        let got = db.get_request_details("test-req-001").await.unwrap().unwrap();
        assert_eq!(got.request_id, "test-req-001");
        assert_eq!(got.req_headers, details.req_headers);
        assert_eq!(got.req_body, details.req_body);
        assert_eq!(got.transformed_url, details.transformed_url);
        assert_eq!(got.transformed_headers, details.transformed_headers);
        assert_eq!(got.transformed_body, details.transformed_body);
        assert_eq!(got.response_status, Some(200));
        assert_eq!(got.response_headers, details.response_headers);
        assert_eq!(got.response_body, details.response_body);
        assert!(!got.body_truncated);
    }

    #[tokio::test]
    async fn test_request_details_not_found() {
        let db = GapDatabase::in_memory().await.unwrap();
        let result = db.get_request_details("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_request_details_partial_data() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Only pre-transform data (e.g., rejected request)
        let details = crate::types::RequestDetails {
            request_id: "rejected-001".to_string(),
            req_headers: Some(r#"{"Host":"blocked.com"}"#.to_string()),
            req_body: None,
            transformed_url: None,
            transformed_headers: None,
            transformed_body: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            body_truncated: false,
        };
        db.save_request_details(&details).await.unwrap();

        let got = db.get_request_details("rejected-001").await.unwrap().unwrap();
        assert_eq!(got.req_headers, Some(r#"{"Host":"blocked.com"}"#.to_string()));
        assert!(got.transformed_url.is_none());
        assert!(got.response_status.is_none());
    }

    #[tokio::test]
    async fn test_request_details_with_truncated_body() {
        let db = GapDatabase::in_memory().await.unwrap();

        let details = crate::types::RequestDetails {
            request_id: "truncated-001".to_string(),
            req_headers: None,
            req_body: Some(vec![0u8; 100]),
            transformed_url: None,
            transformed_headers: None,
            transformed_body: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            body_truncated: true,
        };
        db.save_request_details(&details).await.unwrap();

        let got = db.get_request_details("truncated-001").await.unwrap().unwrap();
        assert!(got.body_truncated);
    }

    // ── Management Log ───────────────────────────────────────────────

    fn sample_management_entry(operation: &str, resource_type: &str) -> ManagementLogEntry {
        ManagementLogEntry {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: None,
            detail: None,
            success: true,
            error_message: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        }
    }

    #[tokio::test]
    async fn test_management_log_round_trip() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ManagementLogEntry {
            timestamp: Utc::now(),
            operation: "token_create".to_string(),
            resource_type: "token".to_string(),
            resource_id: Some("tok_abc123".to_string()),
            detail: Some(r#"{"name":"my-token"}"#.to_string()),
            success: true,
            error_message: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_management_event(&entry).await.unwrap();

        let logs = db.query_management_log(&crate::types::ManagementLogFilter::default()).await.unwrap();
        assert_eq!(logs.len(), 1);
        let got = &logs[0];
        assert_eq!(got.operation, "token_create");
        assert_eq!(got.resource_type, "token");
        assert_eq!(got.resource_id, Some("tok_abc123".to_string()));
        assert_eq!(got.detail, Some(r#"{"name":"my-token"}"#.to_string()));
        assert!(got.success);
        assert_eq!(got.error_message, None);
    }

    #[tokio::test]
    async fn test_management_log_round_trip_failure_entry() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ManagementLogEntry {
            timestamp: Utc::now(),
            operation: "plugin_install".to_string(),
            resource_type: "plugin".to_string(),
            resource_id: Some("exa".to_string()),
            detail: None,
            success: false,
            error_message: Some("Repository not found".to_string()),
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        db.log_management_event(&entry).await.unwrap();

        let logs = db.query_management_log(&crate::types::ManagementLogFilter::default()).await.unwrap();
        assert_eq!(logs.len(), 1);
        let got = &logs[0];
        assert!(!got.success);
        assert_eq!(got.error_message, Some("Repository not found".to_string()));
        assert_eq!(got.detail, None);
    }

    #[tokio::test]
    async fn test_management_log_filter_by_operation() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.log_management_event(&sample_management_entry("token_create", "token")).await.unwrap();
        db.log_management_event(&sample_management_entry("plugin_install", "plugin")).await.unwrap();
        db.log_management_event(&sample_management_entry("token_create", "token")).await.unwrap();

        let filter = crate::types::ManagementLogFilter {
            operation: Some("token_create".to_string()),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 2);
        assert!(logs.iter().all(|e| e.operation == "token_create"));
    }

    #[tokio::test]
    async fn test_management_log_filter_by_resource_type() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.log_management_event(&sample_management_entry("token_create", "token")).await.unwrap();
        db.log_management_event(&sample_management_entry("plugin_install", "plugin")).await.unwrap();
        db.log_management_event(&sample_management_entry("credential_set", "credential")).await.unwrap();

        let filter = crate::types::ManagementLogFilter {
            resource_type: Some("plugin".to_string()),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].operation, "plugin_install");
    }

    #[tokio::test]
    async fn test_management_log_filter_by_success() {
        let db = GapDatabase::in_memory().await.unwrap();

        let mut success_entry = sample_management_entry("token_create", "token");
        success_entry.success = true;
        db.log_management_event(&success_entry).await.unwrap();

        let mut failure_entry = sample_management_entry("plugin_install", "plugin");
        failure_entry.success = false;
        failure_entry.error_message = Some("network error".to_string());
        db.log_management_event(&failure_entry).await.unwrap();

        // Filter for successes only
        let filter = crate::types::ManagementLogFilter {
            success: Some(true),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert!(logs[0].success);
        assert_eq!(logs[0].operation, "token_create");

        // Filter for failures only
        let filter = crate::types::ManagementLogFilter {
            success: Some(false),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert!(!logs[0].success);
        assert_eq!(logs[0].operation, "plugin_install");
    }

    #[tokio::test]
    async fn test_management_log_filter_by_since() {
        let db = GapDatabase::in_memory().await.unwrap();

        let old_time = Utc::now() - Duration::hours(2);
        let cutoff = Utc::now() - Duration::minutes(30);
        let new_time = Utc::now();

        let mut old_entry = sample_management_entry("token_create", "token");
        old_entry.timestamp = old_time;
        db.log_management_event(&old_entry).await.unwrap();

        let mut new_entry = sample_management_entry("plugin_install", "plugin");
        new_entry.timestamp = new_time;
        db.log_management_event(&new_entry).await.unwrap();

        let filter = crate::types::ManagementLogFilter {
            since: Some(cutoff),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].operation, "plugin_install");
    }

    #[tokio::test]
    async fn test_management_log_limit() {
        let db = GapDatabase::in_memory().await.unwrap();

        for i in 0..3 {
            let mut entry = sample_management_entry("token_create", "token");
            entry.timestamp = Utc::now() + Duration::seconds(i);
            db.log_management_event(&entry).await.unwrap();
        }

        let filter = crate::types::ManagementLogFilter {
            limit: Some(2),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn test_management_log_empty_query_returns_all() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.log_management_event(&sample_management_entry("token_create", "token")).await.unwrap();
        db.log_management_event(&sample_management_entry("plugin_install", "plugin")).await.unwrap();
        db.log_management_event(&sample_management_entry("credential_set", "credential")).await.unwrap();

        // Default filter with no constraints
        let logs = db.query_management_log(&crate::types::ManagementLogFilter::default()).await.unwrap();
        assert_eq!(logs.len(), 3);
    }

    #[tokio::test]
    async fn test_management_log_filter_by_resource_id() {
        let db = GapDatabase::in_memory().await.unwrap();

        let mut entry_a = sample_management_entry("token_create", "token");
        entry_a.resource_id = Some("tok_aaa".to_string());
        db.log_management_event(&entry_a).await.unwrap();

        let mut entry_b = sample_management_entry("token_delete", "token");
        entry_b.resource_id = Some("tok_bbb".to_string());
        db.log_management_event(&entry_b).await.unwrap();

        let filter = crate::types::ManagementLogFilter {
            resource_id: Some("tok_aaa".to_string()),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].resource_id, Some("tok_aaa".to_string()));
    }

    // ── Header Set CRUD ───────────────────────────────────────────

    #[tokio::test]
    async fn test_header_set_crud() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Create a header set
        let id = db.add_header_set(&["api.example.com".to_string()], 10, "default", "default")
            .await
            .unwrap();

        // Get it back
        let hs = db.get_header_set(&id, "default", "default").await.unwrap().unwrap();
        assert_eq!(hs.id, id);
        assert_eq!(hs.match_patterns, vec!["api.example.com".to_string()]);
        assert_eq!(hs.weight, 10);

        // List should contain it
        let all = db.list_header_sets("default", "default").await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, id);

        // Update patterns
        db.update_header_set(
            &id,
            Some(&["api.example.com".to_string(), "*.example.org".to_string()]),
            None,
            "default",
            "default",
        )
        .await
        .unwrap();
        let hs = db.get_header_set(&id, "default", "default").await.unwrap().unwrap();
        assert_eq!(hs.match_patterns.len(), 2);

        // Update weight
        db.update_header_set(&id, None, Some(20), "default", "default")
            .await
            .unwrap();
        let hs = db.get_header_set(&id, "default", "default").await.unwrap().unwrap();
        assert_eq!(hs.weight, 20);

        // Soft delete
        db.remove_header_set(&id, "default", "default").await.unwrap();
        assert!(db.get_header_set(&id, "default", "default").await.unwrap().is_none());
        assert_eq!(db.list_header_sets("default", "default").await.unwrap().len(), 0);

        // Re-create gets a new UUID (no upsert with UUIDs)
        let id2 = db.add_header_set(&["new.example.com".to_string()], 5, "default", "default")
            .await
            .unwrap();
        let hs = db.get_header_set(&id2, "default", "default").await.unwrap().unwrap();
        assert_eq!(hs.match_patterns, vec!["new.example.com".to_string()]);
        assert_eq!(hs.weight, 5);
    }

    #[tokio::test]
    async fn test_header_set_headers() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Create a header set
        let id = db.add_header_set(&["api.example.com".to_string()], 0, "default", "default")
            .await
            .unwrap();

        // Set some headers
        db.set_header_set_header(&id, "Authorization", "Bearer token123", "default", "default")
            .await
            .unwrap();
        db.set_header_set_header(&id, "X-Custom", "value1", "default", "default")
            .await
            .unwrap();

        // Get headers with values
        let headers = db.get_header_set_headers(&id, "default", "default").await.unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("Authorization").unwrap(), "Bearer token123");
        assert_eq!(headers.get("X-Custom").unwrap(), "value1");

        // List header names
        let names = db
            .list_header_set_header_names(&id, "default", "default")
            .await
            .unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Authorization".to_string()));
        assert!(names.contains(&"X-Custom".to_string()));

        // Remove one header
        db.remove_header_set_header(&id, "X-Custom", "default", "default")
            .await
            .unwrap();
        let names = db
            .list_header_set_header_names(&id, "default", "default")
            .await
            .unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "Authorization");

        // Cascade on header set delete: removing the header set should also remove headers
        db.remove_header_set(&id, "default", "default").await.unwrap();
        let headers = db.get_header_set_headers(&id, "default", "default").await.unwrap();
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn test_plugin_weight() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Add plugin with default weight=0
        let plugin = sample_plugin("placeholder");
        let id = db.add_plugin(&plugin, "src", "default", "default").await.unwrap();

        let got = db.get_plugin(&id, "default", "default").await.unwrap().unwrap();
        assert_eq!(got.weight, 0);

        // Update weight
        db.update_plugin_weight(&id, 42, "default", "default").await.unwrap();

        // Verify via list_plugins
        let plugins = db.list_plugins("default", "default").await.unwrap();
        let p = plugins.iter().find(|p| p.id == id).unwrap();
        assert_eq!(p.weight, 42);
    }

    #[tokio::test]
    async fn test_plugin_installed_at() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin = sample_plugin("placeholder");
        let id = db.add_plugin(&plugin, "src", "default", "default").await.unwrap();

        let got = db.get_plugin(&id, "default", "default").await.unwrap().unwrap();
        assert!(
            got.installed_at.is_some(),
            "installed_at should be populated from DB"
        );
    }

    // ── Namespace Isolation ──────────────────────────────────────────

    #[tokio::test]
    async fn test_plugin_namespace_isolation() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Add plugin in org1/team1
        let plugin = sample_plugin("placeholder");
        let id = db.add_plugin(&plugin, "function transform() {}", "org1", "team1").await.unwrap();

        // Visible from org1/team1
        assert!(db.get_plugin(&id, "org1", "team1").await.unwrap().is_some());
        assert!(db.has_plugin(&id, "org1", "team1").await.unwrap());
        assert_eq!(db.list_plugins("org1", "team1").await.unwrap().len(), 1);
        assert!(db.get_plugin_source(&id, "org1", "team1").await.unwrap().is_some());

        // NOT visible from org1/team2 (different scope)
        assert!(db.get_plugin(&id, "org1", "team2").await.unwrap().is_none());
        assert!(!db.has_plugin(&id, "org1", "team2").await.unwrap());
        assert_eq!(db.list_plugins("org1", "team2").await.unwrap().len(), 0);
        assert!(db.get_plugin_source(&id, "org1", "team2").await.unwrap().is_none());

        // NOT visible from org2/team1 (different namespace)
        assert!(db.get_plugin(&id, "org2", "team1").await.unwrap().is_none());
        assert!(!db.has_plugin(&id, "org2", "team1").await.unwrap());
        assert_eq!(db.list_plugins("org2", "team1").await.unwrap().len(), 0);

        // NOT visible from default/default
        assert!(db.get_plugin(&id, "default", "default").await.unwrap().is_none());
        assert_eq!(db.list_plugins("default", "default").await.unwrap().len(), 0);

        // Verify returned entry has correct namespace/scope
        let got = db.get_plugin(&id, "org1", "team1").await.unwrap().unwrap();
        assert_eq!(got.namespace_id, "org1");
        assert_eq!(got.scope_id, "team1");

        // Verify list_plugins returns entries with correct namespace/scope
        let plugins = db.list_plugins("org1", "team1").await.unwrap();
        assert_eq!(plugins[0].namespace_id, "org1");
        assert_eq!(plugins[0].scope_id, "team1");

        // Verify remove_plugin respects namespace/scope
        db.remove_plugin(&id, "org1", "team2").await.unwrap(); // wrong scope - should not affect
        assert!(db.has_plugin(&id, "org1", "team1").await.unwrap()); // still visible
        db.remove_plugin(&id, "org1", "team1").await.unwrap(); // correct scope
        assert!(!db.has_plugin(&id, "org1", "team1").await.unwrap()); // now gone

        // Verify get_plugin_version_by_hash respects namespace/scope
        let source_hash = format!("{:x}", sha2::Sha256::digest("function transform() {}".as_bytes()));
        assert!(db.get_plugin_version_by_hash(&source_hash, "org1", "team1").await.unwrap().is_some());
        assert!(db.get_plugin_version_by_hash(&source_hash, "org1", "team2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_credential_namespace_isolation() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Set credential in org1/team1
        db.set_credential("plugin-1", "api_key", "secret-for-team1", "org1", "team1")
            .await
            .unwrap();

        // Visible from org1/team1
        let val = db.get_credential("plugin-1", "api_key", "org1", "team1").await.unwrap();
        assert_eq!(val, Some("secret-for-team1".to_string()));

        // NOT visible from org1/team2
        let val = db.get_credential("plugin-1", "api_key", "org1", "team2").await.unwrap();
        assert!(val.is_none());

        // NOT visible from org2/team1
        let val = db.get_credential("plugin-1", "api_key", "org2", "team1").await.unwrap();
        assert!(val.is_none());

        // NOT visible from default/default
        let val = db.get_credential("plugin-1", "api_key", "default", "default").await.unwrap();
        assert!(val.is_none());

        // get_plugin_credentials also isolated
        let creds = db.get_plugin_credentials("plugin-1", "org1", "team1").await.unwrap();
        assert!(creds.is_some());
        assert_eq!(creds.unwrap().get("api_key").unwrap(), "secret-for-team1");

        let creds = db.get_plugin_credentials("plugin-1", "org1", "team2").await.unwrap();
        assert!(creds.is_none());

        // list_credentials isolated
        let creds = db.list_credentials("org1", "team1").await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].namespace_id, "org1");
        assert_eq!(creds[0].scope_id, "team1");

        let creds = db.list_credentials("org1", "team2").await.unwrap();
        assert_eq!(creds.len(), 0);

        // remove_credential isolated
        db.remove_credential("plugin-1", "api_key", "org1", "team2").await.unwrap(); // wrong scope
        assert!(db.get_credential("plugin-1", "api_key", "org1", "team1").await.unwrap().is_some()); // still there

        db.remove_credential("plugin-1", "api_key", "org1", "team1").await.unwrap(); // correct scope
        assert!(db.get_credential("plugin-1", "api_key", "org1", "team1").await.unwrap().is_none()); // now gone
    }

    #[tokio::test]
    async fn test_token_namespace_isolation() {
        let db = GapDatabase::in_memory().await.unwrap();
        let now = Utc::now();

        // Create token in org1/team1
        db.add_token("gap_iso_token_01", now, None, "org1", "team1").await.unwrap();

        // Visible from org1/team1
        assert!(db.get_token("gap_iso_token_01", "org1", "team1").await.unwrap().is_some());
        assert_eq!(db.list_tokens(false, "org1", "team1").await.unwrap().len(), 1);
        assert!(db.get_token_by_prefix("gap_iso_token", "org1", "team1").await.unwrap().is_some());

        // NOT visible from org2/team1 (different namespace)
        assert!(db.get_token("gap_iso_token_01", "org2", "team1").await.unwrap().is_none());
        assert_eq!(db.list_tokens(false, "org2", "team1").await.unwrap().len(), 0);
        assert!(db.get_token_by_prefix("gap_iso_token", "org2", "team1").await.unwrap().is_none());

        // NOT visible from org1/team2 (different scope)
        assert!(db.get_token("gap_iso_token_01", "org1", "team2").await.unwrap().is_none());
        assert_eq!(db.list_tokens(false, "org1", "team2").await.unwrap().len(), 0);

        // NOT visible from default/default
        assert!(db.get_token("gap_iso_token_01", "default", "default").await.unwrap().is_none());
        assert_eq!(db.list_tokens(false, "default", "default").await.unwrap().len(), 0);

        // Verify returned entry has correct namespace/scope
        let meta = db.get_token("gap_iso_token_01", "org1", "team1").await.unwrap().unwrap();
        assert_eq!(meta.namespace_id, "org1");
        assert_eq!(meta.scope_id, "team1");

        let tokens = db.list_tokens(false, "org1", "team1").await.unwrap();
        assert_eq!(tokens[0].namespace_id, "org1");
        assert_eq!(tokens[0].scope_id, "team1");

        // Revoke from wrong scope has no effect
        db.revoke_token("gap_iso_token_01", "org1", "team2").await.unwrap();
        assert!(db.get_token("gap_iso_token_01", "org1", "team1").await.unwrap().is_some());

        // Revoke from correct scope works
        db.revoke_token("gap_iso_token_01", "org1", "team1").await.unwrap();
        assert!(db.get_token("gap_iso_token_01", "org1", "team1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_header_set_namespace_isolation() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Add header set in org1/team1
        let id = db.add_header_set(&["api.example.com".to_string()], 10, "org1", "team1")
            .await
            .unwrap();

        // Visible from org1/team1
        assert!(db.get_header_set(&id, "org1", "team1").await.unwrap().is_some());
        assert_eq!(db.list_header_sets("org1", "team1").await.unwrap().len(), 1);

        // NOT visible from org1/team2 (different scope)
        assert!(db.get_header_set(&id, "org1", "team2").await.unwrap().is_none());
        assert_eq!(db.list_header_sets("org1", "team2").await.unwrap().len(), 0);

        // NOT visible from org2/team1 (different namespace)
        assert!(db.get_header_set(&id, "org2", "team1").await.unwrap().is_none());
        assert_eq!(db.list_header_sets("org2", "team1").await.unwrap().len(), 0);

        // NOT visible from default/default
        assert!(db.get_header_set(&id, "default", "default").await.unwrap().is_none());
        assert_eq!(db.list_header_sets("default", "default").await.unwrap().len(), 0);

        // Verify returned entry has correct namespace/scope
        let hs = db.get_header_set(&id, "org1", "team1").await.unwrap().unwrap();
        assert_eq!(hs.namespace_id, "org1");
        assert_eq!(hs.scope_id, "team1");

        let all = db.list_header_sets("org1", "team1").await.unwrap();
        assert_eq!(all[0].namespace_id, "org1");
        assert_eq!(all[0].scope_id, "team1");

        // Update from wrong scope fails
        assert!(db.update_header_set(&id, None, Some(99), "org1", "team2").await.is_err());

        // Update from correct scope works
        db.update_header_set(&id, None, Some(99), "org1", "team1").await.unwrap();
        let hs = db.get_header_set(&id, "org1", "team1").await.unwrap().unwrap();
        assert_eq!(hs.weight, 99);

        // Remove from wrong scope has no effect
        db.remove_header_set(&id, "org1", "team2").await.unwrap();
        assert!(db.get_header_set(&id, "org1", "team1").await.unwrap().is_some());

        // Remove from correct scope works
        db.remove_header_set(&id, "org1", "team1").await.unwrap();
        assert!(db.get_header_set(&id, "org1", "team1").await.unwrap().is_none());
    }
