//! JavaScript plugin runtime using Boa engine
//!
//! Provides a sandboxed JavaScript environment for executing plugin transforms.
//! Implements:
//! - ACP.crypto globals (sha256, sha256Hex, hmac)
//! - ACP.util globals (base64, hex, now, isoDate, amzDate)
//! - TextEncoder/TextDecoder
//! - Sandbox restrictions (no fetch, eval, etc.)

use crate::storage::SecretStore;
use crate::types::{ACPCredentials, ACPPlugin, ACPRequest};
use crate::{AcpError, Result};
use base64::Engine;
use boa_engine::{Context, JsArgs, JsNativeError, JsResult, JsString, JsValue, NativeFunction, Source};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

/// JavaScript runtime for plugin execution
pub struct PluginRuntime {
    context: Context,
    plugins: HashMap<String, ACPPlugin>,
}

impl PluginRuntime {
    /// Create a new plugin runtime with sandboxed global objects
    pub fn new() -> Result<Self> {
        let mut context = Context::default();

        // Set up ACP global object (including log functionality)
        Self::setup_acp_globals(&mut context)?;

        // Set up TextEncoder/TextDecoder
        Self::setup_text_encoding(&mut context)?;

        // Set up URL and URLSearchParams
        Self::setup_url_apis(&mut context)?;

        // Apply sandbox restrictions
        Self::apply_sandbox(&mut context)?;

        Ok(Self {
            context,
            plugins: HashMap::new(),
        })
    }

    /// Execute JavaScript code in the runtime
    pub fn execute(&mut self, code: &str) -> Result<JsValue> {
        self.context
            .eval(Source::from_bytes(code))
            .map_err(|e| AcpError::plugin(format!("JavaScript execution error: {}", e)))
    }

    /// Set up ACP.crypto and ACP.util global objects
    fn setup_acp_globals(context: &mut Context) -> Result<()> {
        // Register native functions first
        Self::register_crypto_natives(context)?;
        Self::register_util_natives(context)?;
        Self::register_log_native(context)?;

        // Create ACP namespace with crypto, util, and log methods
        let setup_code = r#"
        var ACP = {
            crypto: {
                sha256: function(data) {
                    return __acp_native_sha256(data);
                },
                sha256Hex: function(data) {
                    return __acp_native_sha256_hex(data);
                },
                hmac: function(key, data, encoding) {
                    return __acp_native_hmac(key, data, encoding || 'hex');
                }
            },
            util: {
                base64: function(data, decode) {
                    if (decode) {
                        return __acp_native_base64_decode(data);
                    }
                    return __acp_native_base64_encode(data);
                },
                hex: function(data, decode) {
                    if (decode) {
                        return __acp_native_hex_decode(data);
                    }
                    return __acp_native_hex_encode(data);
                },
                now: function() {
                    return __acp_native_now();
                },
                isoDate: function(timestamp) {
                    return __acp_native_iso_date(timestamp);
                },
                amzDate: function(timestamp) {
                    return __acp_native_amz_date(timestamp);
                }
            },
            log: function(msg) {
                __acp_native_log(msg);
            }
        };
        "#;

        context.eval(Source::from_bytes(setup_code))
            .map_err(|e| AcpError::plugin(format!("Failed to create ACP namespace: {}", e)))?;

        Ok(())
    }

    /// Register native crypto functions
    fn register_crypto_natives(context: &mut Context) -> Result<()> {
        // sha256 - returns array of bytes
        let sha256_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let data = args.get_or_undefined(0);
            let bytes = js_value_to_bytes(data, context)?;

            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let result = hasher.finalize();

            bytes_to_js_array(&result, context)
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_sha256"),
            1,
            sha256_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register sha256: {}", e)))?;

        // sha256Hex - returns hex string
        let sha256_hex_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let data = args.get_or_undefined(0);
            let bytes = js_value_to_bytes(data, context)?;

            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let result = hasher.finalize();

            Ok(JsValue::from(JsString::from(hex::encode(result))))
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_sha256_hex"),
            1,
            sha256_hex_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register sha256Hex: {}", e)))?;

        // hmac - returns encoded string
        let hmac_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let key = args.get_or_undefined(0);
            let data = args.get_or_undefined(1);
            let encoding = args.get_or_undefined(2);

            let key_bytes = js_value_to_bytes(key, context)?;
            let data_bytes = js_value_to_bytes(data, context)?;
            let encoding_str = if let Some(s) = encoding.as_string() {
                s.to_std_string_escaped()
            } else {
                "hex".to_string()
            };

            let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
                .map_err(|e| JsNativeError::typ().with_message(format!("HMAC key error: {}", e)))?;
            mac.update(&data_bytes);
            let result = mac.finalize().into_bytes();

            match encoding_str.as_str() {
                "hex" => Ok(JsValue::from(JsString::from(hex::encode(result)))),
                "base64" => Ok(JsValue::from(JsString::from(base64::prelude::BASE64_STANDARD.encode(result)))),
                _ => bytes_to_js_array(&result, context),
            }
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_hmac"),
            3,
            hmac_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register hmac: {}", e)))?;

        Ok(())
    }

    /// Register native util functions
    fn register_util_natives(context: &mut Context) -> Result<()> {
        use base64::prelude::*;

        // base64 encode
        let base64_encode_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let data = args.get_or_undefined(0);
            let bytes = js_value_to_bytes(data, context)?;
            Ok(JsValue::from(JsString::from(BASE64_STANDARD.encode(&bytes))))
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_base64_encode"),
            1,
            base64_encode_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register base64 encode: {}", e)))?;

        // base64 decode
        let base64_decode_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let data = args.get_or_undefined(0);
            let s = if let Some(js_str) = data.as_string() {
                js_str.to_std_string_escaped()
            } else {
                return Err(JsNativeError::typ()
                    .with_message("Expected string for base64 decode")
                    .into());
            };

            let bytes = BASE64_STANDARD.decode(s.as_bytes())
                .map_err(|e| JsNativeError::typ().with_message(format!("Base64 decode error: {}", e)))?;

            bytes_to_js_array(&bytes, context)
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_base64_decode"),
            1,
            base64_decode_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register base64 decode: {}", e)))?;

        // hex encode
        let hex_encode_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let data = args.get_or_undefined(0);
            let bytes = js_value_to_bytes(data, context)?;
            Ok(JsValue::from(JsString::from(hex::encode(&bytes))))
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_hex_encode"),
            1,
            hex_encode_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register hex encode: {}", e)))?;

        // hex decode
        let hex_decode_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let data = args.get_or_undefined(0);
            let s = if let Some(js_str) = data.as_string() {
                js_str.to_std_string_escaped()
            } else {
                return Err(JsNativeError::typ()
                    .with_message("Expected string for hex decode")
                    .into());
            };

            let bytes = hex::decode(s)
                .map_err(|e| JsNativeError::typ().with_message(format!("Hex decode error: {}", e)))?;

            bytes_to_js_array(&bytes, context)
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_hex_decode"),
            1,
            hex_decode_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register hex decode: {}", e)))?;

        // now - returns current timestamp in milliseconds
        let now_fn = NativeFunction::from_fn_ptr(|_, _, _| {
            let now = Utc::now().timestamp_millis();
            Ok(JsValue::from(now))
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_now"),
            0,
            now_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register now: {}", e)))?;

        // isoDate - formats timestamp as ISO 8601 date string
        let iso_date_fn = NativeFunction::from_fn_ptr(|_, args, _| {
            let timestamp = args.get_or_undefined(0);
            let ts = timestamp.as_number()
                .ok_or_else(|| JsNativeError::typ().with_message("Expected number for timestamp"))?;

            let dt = chrono::DateTime::from_timestamp_millis(ts as i64)
                .ok_or_else(|| JsNativeError::typ().with_message("Invalid timestamp"))?;

            Ok(JsValue::from(JsString::from(dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())))
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_iso_date"),
            1,
            iso_date_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register isoDate: {}", e)))?;

        // amzDate - formats timestamp as AWS date string (YYYYMMDD'T'HHMMSS'Z')
        let amz_date_fn = NativeFunction::from_fn_ptr(|_, args, _| {
            let timestamp = args.get_or_undefined(0);
            let ts = timestamp.as_number()
                .ok_or_else(|| JsNativeError::typ().with_message("Expected number for timestamp"))?;

            let dt = chrono::DateTime::from_timestamp_millis(ts as i64)
                .ok_or_else(|| JsNativeError::typ().with_message("Invalid timestamp"))?;

            Ok(JsValue::from(JsString::from(dt.format("%Y%m%dT%H%M%SZ").to_string())))
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_amz_date"),
            1,
            amz_date_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register amzDate: {}", e)))?;

        Ok(())
    }

    /// Register native log function for ACP.log
    fn register_log_native(context: &mut Context) -> Result<()> {
        // Create a JavaScript array to store logs
        let setup_log_code = r#"
        var __acp_logs = [];
        function __acp_native_log(msg) {
            // Convert to string
            var str;
            if (typeof msg === 'string') {
                str = msg;
            } else if (typeof msg === 'number') {
                str = String(msg);
            } else if (typeof msg === 'boolean') {
                str = String(msg);
            } else if (msg === null) {
                str = 'null';
            } else if (msg === undefined) {
                str = 'undefined';
            } else {
                // For objects, try JSON.stringify
                try {
                    str = JSON.stringify(msg);
                } catch (e) {
                    str = String(msg);
                }
            }
            __acp_logs.push(str);
        }
        "#;

        context.eval(Source::from_bytes(setup_log_code))
            .map_err(|e| AcpError::plugin(format!("Failed to create log function: {}", e)))?;

        Ok(())
    }

    /// Get all captured log messages
    pub fn get_logs(&mut self) -> Vec<String> {
        // Access the JavaScript __acp_logs array
        let global = self.context.global_object();
        let logs_value = global.get(JsString::from("__acp_logs"), &mut self.context)
            .unwrap_or(JsValue::undefined());

        if let Some(logs_obj) = logs_value.as_object() {
            let length_value = logs_obj.get(JsString::from("length"), &mut self.context)
                .unwrap_or(JsValue::from(0));

            if let Some(length) = length_value.as_number() {
                let len = length as usize;
                let mut result = Vec::new();
                for i in 0..len {
                    if let Ok(elem) = logs_obj.get(i, &mut self.context) {
                        if let Some(s) = elem.as_string() {
                            result.push(s.to_std_string_escaped());
                        }
                    }
                }
                return result;
            }
        }

        Vec::new()
    }

    /// Clear all captured log messages
    pub fn clear_logs(&mut self) {
        // Clear the JavaScript __acp_logs array
        let _ = self.context.eval(Source::from_bytes("__acp_logs = [];"));
    }

    /// Set up TextEncoder and TextDecoder
    fn setup_text_encoding(context: &mut Context) -> Result<()> {
        // Register native encode/decode functions
        let encode_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let text = args.get_or_undefined(0);
            let s = if let Some(js_str) = text.as_string() {
                js_str.to_std_string_escaped()
            } else {
                return Err(JsNativeError::typ()
                    .with_message("Expected string")
                    .into());
            };

            bytes_to_js_array(s.as_bytes(), context)
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_text_encode"),
            1,
            encode_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register text encode: {}", e)))?;

        let decode_fn = NativeFunction::from_fn_ptr(|_, args, context| {
            let data = args.get_or_undefined(0);
            let bytes = js_value_to_bytes(data, context)?;

            let s = String::from_utf8(bytes)
                .map_err(|e| JsNativeError::typ().with_message(format!("UTF-8 decode error: {}", e)))?;

            Ok(JsValue::from(JsString::from(s)))
        });
        context.register_global_builtin_callable(
            JsString::from("__acp_native_text_decode"),
            1,
            decode_fn
        ).map_err(|e| AcpError::plugin(format!("Failed to register text decode: {}", e)))?;

        // Create TextEncoder and TextDecoder classes
        let text_code = r#"
        function TextEncoder() {}
        TextEncoder.prototype.encode = function(str) {
            return __acp_native_text_encode(str);
        };

        function TextDecoder() {}
        TextDecoder.prototype.decode = function(bytes) {
            return __acp_native_text_decode(bytes);
        };
        "#;
        context.eval(Source::from_bytes(text_code))
            .map_err(|e| AcpError::plugin(format!("Failed to create TextEncoder/TextDecoder: {}", e)))?;

        Ok(())
    }

    /// Set up URL and URLSearchParams global objects
    ///
    /// Provides pure JavaScript implementations for URL parsing and manipulation.
    fn setup_url_apis(context: &mut Context) -> Result<()> {
        let url_code = r#"
        function URLSearchParams(init) {
            this.params = {};

            if (typeof init === 'string') {
                if (init.startsWith('?')) {
                    init = init.substring(1);
                }
                if (init) {
                    var pairs = init.split('&');
                    for (var i = 0; i < pairs.length; i++) {
                        var pair = pairs[i].split('=');
                        var key = decodeURIComponent(pair[0]);
                        var value = pair[1] ? decodeURIComponent(pair[1]) : '';
                        this.params[key] = value;
                    }
                }
            }
        }

        URLSearchParams.prototype.get = function(name) {
            return this.params[name] || null;
        };

        URLSearchParams.prototype.set = function(name, value) {
            this.params[name] = String(value);
        };

        URLSearchParams.prototype.has = function(name) {
            return this.params.hasOwnProperty(name);
        };

        URLSearchParams.prototype.delete = function(name) {
            delete this.params[name];
        };

        URLSearchParams.prototype.toString = function() {
            var parts = [];
            for (var key in this.params) {
                if (this.params.hasOwnProperty(key)) {
                    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(this.params[key]));
                }
            }
            return parts.join('&');
        };

        function URL(urlString) {
            // Simple regex-based URL parser
            var match = urlString.match(/^(([^:/?#]+):)?(\/\/([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/);

            this.protocol = match[2] ? match[2] + ':' : '';
            this.hostname = '';
            this.port = '';
            this.pathname = match[5] || '/';
            this.search = match[6] || '';
            this.hash = match[8] ? '#' + match[9] : '';

            // Parse host:port
            if (match[4]) {
                var hostPort = match[4].split(':');
                this.hostname = hostPort[0];
                this.port = hostPort[1] || '';
            }

            this.host = this.port ? this.hostname + ':' + this.port : this.hostname;
            this.origin = this.protocol + '//' + this.host;
            this.href = urlString;

            // Parse search params
            this.searchParams = new URLSearchParams(this.search);
        }

        URL.prototype.toString = function() {
            return this.href;
        };
        "#;

        context.eval(Source::from_bytes(url_code))
            .map_err(|e| AcpError::plugin(format!("Failed to create URL/URLSearchParams: {}", e)))?;

        Ok(())
    }

    /// Apply sandbox restrictions
    fn apply_sandbox(context: &mut Context) -> Result<()> {
        // Block dangerous globals by setting them to undefined or throwing functions
        let sandbox_code = r#"
        // Block network access
        if (typeof fetch !== 'undefined') {
            fetch = function() { throw new Error('fetch is not allowed in plugin sandbox'); };
        }
        if (typeof XMLHttpRequest !== 'undefined') {
            XMLHttpRequest = function() { throw new Error('XMLHttpRequest is not allowed in plugin sandbox'); };
        }

        // Block dynamic code evaluation
        if (typeof eval !== 'undefined') {
            eval = function() { throw new Error('eval is not allowed in plugin sandbox'); };
        }
        if (typeof Function !== 'undefined') {
            const OriginalFunction = Function;
            Function = function() { throw new Error('Function constructor is not allowed in plugin sandbox'); };
            Function.prototype = OriginalFunction.prototype;
        }

        // Block WebAssembly
        if (typeof WebAssembly !== 'undefined') {
            WebAssembly = undefined;
        }
        "#;

        context.eval(Source::from_bytes(sandbox_code))
            .map_err(|e| AcpError::plugin(format!("Failed to apply sandbox: {}", e)))?;

        Ok(())
    }

    /// Load a plugin from JavaScript code string
    ///
    /// Executes the plugin code and extracts/caches the plugin metadata.
    ///
    /// # Arguments
    /// * `name` - Expected plugin name
    /// * `code` - JavaScript code to execute
    ///
    /// # Returns
    /// The loaded ACPPlugin with metadata
    pub fn load_plugin_from_code(&mut self, name: &str, code: &str) -> Result<ACPPlugin> {
        // Execute the plugin code
        self.execute(code)?;

        // Extract metadata
        let plugin = self.extract_plugin_metadata(name)?;

        // Cache the plugin
        self.plugins.insert(name.to_string(), plugin.clone());

        Ok(plugin)
    }

    /// Load a plugin from the SecretStore and execute it
    ///
    /// Loads the plugin JavaScript code from the store (key: `plugin:{name}`),
    /// executes it, and extracts the plugin metadata object.
    ///
    /// # Arguments
    /// * `name` - Plugin name to load
    /// * `store` - SecretStore to retrieve plugin code from
    ///
    /// # Returns
    /// The loaded ACPPlugin with metadata
    pub async fn load_plugin<S: SecretStore>(&mut self, name: &str, store: &S) -> Result<ACPPlugin> {
        // Retrieve plugin code from store
        let key = format!("plugin:{}", name);
        let code = store.get(&key).await?
            .ok_or_else(|| AcpError::plugin(format!("Plugin '{}' not found in store", name)))?;

        let code_str = String::from_utf8(code)
            .map_err(|e| AcpError::plugin(format!("Plugin code is not valid UTF-8: {}", e)))?;

        // Use the common code loading logic
        self.load_plugin_from_code(name, &code_str)
    }

    /// Extract plugin metadata from the JavaScript context
    ///
    /// Reads the `plugin` object from the JS context and validates its structure.
    ///
    /// # Arguments
    /// * `expected_name` - Expected plugin name for validation
    ///
    /// # Returns
    /// ACPPlugin with extracted metadata
    pub fn extract_plugin_metadata(&mut self, expected_name: &str) -> Result<ACPPlugin> {
        // Get the plugin object from global scope
        let global = self.context.global_object();
        let plugin_key = JsString::from("plugin");
        let plugin_obj = global.get(plugin_key, &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get plugin object: {}", e)))?;

        let plugin_obj = plugin_obj.as_object()
            .ok_or_else(|| AcpError::plugin("plugin is not an object"))?;

        // Extract name
        let name_value = plugin_obj.get(JsString::from("name"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get plugin.name: {}", e)))?;
        let name = name_value.as_string()
            .ok_or_else(|| AcpError::plugin("plugin.name is not a string"))?
            .to_std_string_escaped();

        // Validate name matches expected
        if name != expected_name {
            return Err(AcpError::plugin(format!(
                "Plugin name mismatch: expected '{}', got '{}'",
                expected_name, name
            )));
        }

        // Extract matchPatterns (array of strings)
        let patterns_value = plugin_obj.get(JsString::from("matchPatterns"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get plugin.matchPatterns: {}", e)))?;
        let patterns_obj = patterns_value.as_object()
            .ok_or_else(|| AcpError::plugin("plugin.matchPatterns is not an array"))?;

        let mut match_patterns = Vec::new();
        let length_value = patterns_obj.get(JsString::from("length"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get matchPatterns.length: {}", e)))?;
        let length = length_value.as_number()
            .ok_or_else(|| AcpError::plugin("matchPatterns.length is not a number"))? as usize;

        for i in 0..length {
            let elem = patterns_obj.get(i, &mut self.context)
                .map_err(|e| AcpError::plugin(format!("Failed to get matchPatterns[{}]: {}", i, e)))?;
            let pattern = elem.as_string()
                .ok_or_else(|| AcpError::plugin(format!("matchPatterns[{}] is not a string", i)))?
                .to_std_string_escaped();
            match_patterns.push(pattern);
        }

        // Extract credentialSchema (array of strings)
        let schema_value = plugin_obj.get(JsString::from("credentialSchema"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get plugin.credentialSchema: {}", e)))?;
        let schema_obj = schema_value.as_object()
            .ok_or_else(|| AcpError::plugin("plugin.credentialSchema is not an array"))?;

        let mut credential_schema = Vec::new();
        let schema_length_value = schema_obj.get(JsString::from("length"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get credentialSchema.length: {}", e)))?;
        let schema_length = schema_length_value.as_number()
            .ok_or_else(|| AcpError::plugin("credentialSchema.length is not a number"))? as usize;

        for i in 0..schema_length {
            let elem = schema_obj.get(i, &mut self.context)
                .map_err(|e| AcpError::plugin(format!("Failed to get credentialSchema[{}]: {}", i, e)))?;
            let key = elem.as_string()
                .ok_or_else(|| AcpError::plugin(format!("credentialSchema[{}] is not a string", i)))?
                .to_std_string_escaped();
            credential_schema.push(key);
        }

        // Verify transform function exists
        let transform_value = plugin_obj.get(JsString::from("transform"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get plugin.transform: {}", e)))?;
        let _transform_fn = transform_value.as_callable()
            .ok_or_else(|| AcpError::plugin("plugin.transform is not a function"))?;

        // For the transform field, we store a placeholder since the actual function
        // is in the JS context and will be called directly
        let transform = "function transform(request, credentials) { /* loaded from store */ }".to_string();

        Ok(ACPPlugin {
            name,
            match_patterns,
            credential_schema,
            transform,
        })
    }

    /// Execute a plugin's transform function
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to execute
    /// * `request` - The HTTP request to transform
    /// * `credentials` - Plugin credentials
    ///
    /// # Returns
    /// The transformed request
    pub fn execute_transform(
        &mut self,
        plugin_name: &str,
        request: ACPRequest,
        credentials: &ACPCredentials,
    ) -> Result<ACPRequest> {
        // Get the plugin
        let _plugin = self.plugins.get(plugin_name)
            .ok_or_else(|| AcpError::plugin(format!("Plugin '{}' not loaded", plugin_name)))?;

        // Convert request to JS object
        let request_js = self.request_to_js(&request)?;

        // Convert credentials to JS object
        let credentials_js = self.credentials_to_js(credentials)?;

        // Get the plugin.transform function
        let global = self.context.global_object();
        let plugin_obj = global.get(JsString::from("plugin"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get plugin object: {}", e)))?;
        let plugin_obj = plugin_obj.as_object()
            .ok_or_else(|| AcpError::plugin("plugin is not an object"))?;

        let transform_value = plugin_obj.get(JsString::from("transform"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get plugin.transform: {}", e)))?;
        let transform_fn = transform_value.as_callable()
            .ok_or_else(|| AcpError::plugin("plugin.transform is not a function"))?;

        // Call transform(request, credentials)
        let result = transform_fn.call(
            &JsValue::undefined(),
            &[request_js, credentials_js],
            &mut self.context
        ).map_err(|e| AcpError::plugin(format!("Transform execution error: {}", e)))?;

        // Convert result back to ACPRequest
        self.js_to_request(&result)
    }

    /// Execute a plugin's transform function with timeout protection
    ///
    /// This wraps execute_transform with a timeout to prevent runaway plugins.
    /// Note: Boa cannot interrupt tight infinite loops, but this catches slow operations.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to execute
    /// * `request` - The HTTP request to transform
    /// * `credentials` - Plugin credentials
    /// * `timeout` - Maximum duration to allow for execution
    ///
    /// # Returns
    /// The transformed request, or an error if timeout is exceeded
    pub async fn execute_transform_with_timeout(
        &mut self,
        plugin_name: &str,
        request: ACPRequest,
        credentials: &ACPCredentials,
        timeout: Duration,
    ) -> Result<ACPRequest> {
        use std::time::Instant;

        let start = Instant::now();

        // Execute the transform (this is synchronous but we can check elapsed time)
        let result = self.execute_transform(plugin_name, request, credentials)?;

        // Check if we exceeded the timeout
        if start.elapsed() > timeout {
            return Err(AcpError::plugin(format!(
                "Plugin execution timeout exceeded: {:?} > {:?}",
                start.elapsed(),
                timeout
            )));
        }

        Ok(result)
    }

    /// Convert ACPRequest to JavaScript object
    fn request_to_js(&mut self, request: &ACPRequest) -> Result<JsValue> {
        // Create request object
        let code = format!(
            r#"(function() {{
                return {{
                    method: {},
                    url: {},
                    headers: {{}},
                    body: []
                }};
            }})()"#,
            serde_json::to_string(&request.method).unwrap(),
            serde_json::to_string(&request.url).unwrap()
        );

        let obj = self.context.eval(Source::from_bytes(&code))
            .map_err(|e| AcpError::plugin(format!("Failed to create request object: {}", e)))?;

        let obj_ref = obj.as_object()
            .ok_or_else(|| AcpError::plugin("Failed to create request object"))?;

        // Set headers
        let headers_obj = obj_ref.get(JsString::from("headers"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get headers object: {}", e)))?;
        let headers_obj = headers_obj.as_object()
            .ok_or_else(|| AcpError::plugin("headers is not an object"))?;

        for (key, value) in &request.headers {
            headers_obj.set(
                JsString::from(key.as_str()),
                JsValue::from(JsString::from(value.as_str())),
                false,
                &mut self.context
            ).map_err(|e| AcpError::plugin(format!("Failed to set header '{}': {}", key, e)))?;
        }

        // Set body as byte array
        let body_array = bytes_to_js_array(&request.body, &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to convert body to array: {}", e)))?;

        obj_ref.set(JsString::from("body"), body_array, false, &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to set body: {}", e)))?;

        Ok(obj)
    }

    /// Convert ACPCredentials to JavaScript object
    fn credentials_to_js(&mut self, credentials: &ACPCredentials) -> Result<JsValue> {
        // Create empty object
        let obj = self.context.eval(Source::from_bytes("({})"))
            .map_err(|e| AcpError::plugin(format!("Failed to create credentials object: {}", e)))?;

        let obj_ref = obj.as_object()
            .ok_or_else(|| AcpError::plugin("Failed to create credentials object"))?;

        // Set each credential
        for (key, value) in &credentials.credentials {
            obj_ref.set(
                JsString::from(key.as_str()),
                JsValue::from(JsString::from(value.as_str())),
                false,
                &mut self.context
            ).map_err(|e| AcpError::plugin(format!("Failed to set credential '{}': {}", key, e)))?;
        }

        Ok(obj)
    }

    /// Convert JavaScript object to ACPRequest
    fn js_to_request(&mut self, value: &JsValue) -> Result<ACPRequest> {
        let obj = value.as_object()
            .ok_or_else(|| AcpError::plugin("Transform result is not an object"))?;

        // Extract method
        let method_value = obj.get(JsString::from("method"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get result.method: {}", e)))?;
        let method = method_value.as_string()
            .ok_or_else(|| AcpError::plugin("result.method is not a string"))?
            .to_std_string_escaped();

        // Extract url
        let url_value = obj.get(JsString::from("url"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get result.url: {}", e)))?;
        let url = url_value.as_string()
            .ok_or_else(|| AcpError::plugin("result.url is not a string"))?
            .to_std_string_escaped();

        // Extract headers
        let headers_value = obj.get(JsString::from("headers"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get result.headers: {}", e)))?;
        let headers_obj = headers_value.as_object()
            .ok_or_else(|| AcpError::plugin("result.headers is not an object"))?;

        let mut headers = HashMap::new();

        // Iterate over header properties
        let props = headers_obj.own_property_keys(&mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get header keys: {}", e)))?;

        for prop_key in props {
            // Get the string representation of the key
            let key_value = headers_obj.get(prop_key.clone(), &mut self.context)
                .map_err(|e| AcpError::plugin(format!("Failed to get header value: {}", e)))?;

            // Convert the PropertyKey to string - use the key directly as it should be a string
            let key = match &prop_key {
                boa_engine::property::PropertyKey::String(s) => s.to_std_string_escaped(),
                _ => continue, // Skip non-string keys (symbols, indices)
            };

            let value = key_value.as_string()
                .ok_or_else(|| AcpError::plugin(format!("Header '{}' is not a string", key)))?
                .to_std_string_escaped();

            headers.insert(key, value);
        }

        // Extract body
        let body_value = obj.get(JsString::from("body"), &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to get result.body: {}", e)))?;
        let body = js_value_to_bytes(&body_value, &mut self.context)
            .map_err(|e| AcpError::plugin(format!("Failed to convert body: {}", e)))?;

        Ok(ACPRequest {
            method,
            url,
            headers,
            body,
        })
    }
}

impl Default for PluginRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create default PluginRuntime")
    }
}

// Helper functions for converting between JS and Rust types

fn js_value_to_bytes(value: &JsValue, context: &mut Context) -> JsResult<Vec<u8>> {
    if let Some(s) = value.as_string() {
        // String -> UTF-8 bytes
        Ok(s.to_std_string_escaped().into_bytes())
    } else if let Some(obj) = value.as_object() {
        // Try to extract as array-like object
        let length_key = JsString::from("length");
        let length_value = obj.get(length_key, context)?;

        if let Some(length) = length_value.as_number() {
            let len = length as usize;
            let mut bytes = Vec::with_capacity(len);
            for i in 0..len {
                let val = obj.get(i, context)?;
                let byte = val.as_number()
                    .ok_or_else(|| JsNativeError::typ().with_message("Array element must be number"))? as u8;
                bytes.push(byte);
            }
            Ok(bytes)
        } else {
            Err(JsNativeError::typ()
                .with_message("Expected array-like object with length property")
                .into())
        }
    } else {
        Err(JsNativeError::typ()
            .with_message("Expected string or array-like object")
            .into())
    }
}

fn bytes_to_js_array(bytes: &[u8], context: &mut Context) -> JsResult<JsValue> {
    // Create a JavaScript array from bytes
    let array = context.eval(Source::from_bytes("[]"))?;
    let array_obj = array.as_object()
        .ok_or_else(|| JsNativeError::typ().with_message("Failed to create array"))?;

    for (i, &byte) in bytes.iter().enumerate() {
        array_obj.set(i, JsValue::from(byte as i32), false, context)?;
    }

    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let runtime = PluginRuntime::new();
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_basic_javascript_execution() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("1 + 1").unwrap();
        assert_eq!(result.as_number().unwrap(), 2.0);
    }

    #[test]
    fn test_acp_crypto_sha256_hex_exists() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("typeof ACP.crypto.sha256Hex").unwrap();
        assert_eq!(result.as_string().unwrap().to_std_string_escaped(), "function");
    }

    #[test]
    fn test_acp_crypto_sha256_hex() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("ACP.crypto.sha256Hex('hello')").unwrap();
        let hash = result.as_string().unwrap().to_std_string_escaped();

        // Expected SHA-256 of "hello"
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_acp_crypto_hmac() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("ACP.crypto.hmac('key', 'message', 'hex')").unwrap();
        let hmac = result.as_string().unwrap().to_std_string_escaped();

        // Expected HMAC-SHA256 of "message" with key "key"
        assert_eq!(hmac, "6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a");
    }

    #[test]
    fn test_acp_util_base64() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("ACP.util.base64('hello')").unwrap();
        let encoded = result.as_string().unwrap().to_std_string_escaped();
        assert_eq!(encoded, "aGVsbG8=");
    }

    #[test]
    fn test_acp_util_hex() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("ACP.util.hex('hello')").unwrap();
        let encoded = result.as_string().unwrap().to_std_string_escaped();
        assert_eq!(encoded, "68656c6c6f");
    }

    #[test]
    fn test_acp_util_now() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("ACP.util.now()").unwrap();
        let now = result.as_number().unwrap();

        // Should be a reasonable timestamp (after 2020)
        assert!(now > 1577836800000.0);
    }

    #[test]
    fn test_acp_util_iso_date() {
        let mut runtime = PluginRuntime::new().unwrap();
        // Use a fixed timestamp: 2024-01-01 00:00:00 UTC = 1704067200000 ms
        let result = runtime.execute("ACP.util.isoDate(1704067200000)").unwrap();
        let date = result.as_string().unwrap().to_std_string_escaped();
        assert!(date.starts_with("2024-01-01T00:00:00"));
    }

    #[test]
    fn test_acp_util_amz_date() {
        let mut runtime = PluginRuntime::new().unwrap();
        // Use a fixed timestamp: 2024-01-01 00:00:00 UTC = 1704067200000 ms
        let result = runtime.execute("ACP.util.amzDate(1704067200000)").unwrap();
        let date = result.as_string().unwrap().to_std_string_escaped();
        assert_eq!(date, "20240101T000000Z");
    }

    #[test]
    fn test_text_encoder() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("new TextEncoder().encode('hello')").unwrap();
        // Result should be an array
        assert!(result.is_object());
    }

    #[test]
    fn test_text_decoder() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("new TextDecoder().decode([104, 101, 108, 108, 111])").unwrap();
        let decoded = result.as_string().unwrap().to_std_string_escaped();
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_sandbox_blocks_fetch() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("fetch('https://example.com')");
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_blocks_eval() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("eval('1 + 1')");
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_blocks_function_constructor() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("new Function('return 1')()");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_plugin() {
        use crate::storage::FileStore;

        let temp_dir = std::env::temp_dir().join(format!("acp_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = FileStore::new(temp_dir.clone()).await.unwrap();

        // Create a simple plugin
        let plugin_code = r#"
        var plugin = {
            name: "test-plugin",
            matchPatterns: ["api.example.com"],
            credentialSchema: ["api_key"],
            transform: function(request, credentials) {
                return request;
            }
        };
        "#;

        store.set("plugin:test-plugin", plugin_code.as_bytes()).await.unwrap();

        let mut runtime = PluginRuntime::new().unwrap();
        let plugin = runtime.load_plugin("test-plugin", &store).await.unwrap();

        assert_eq!(plugin.name, "test-plugin");
        assert_eq!(plugin.match_patterns, vec!["api.example.com"]);
        assert_eq!(plugin.credential_schema, vec!["api_key"]);

        // Cleanup
        tokio::fs::remove_dir_all(temp_dir).await.ok();
    }

    #[test]
    fn test_extract_plugin_metadata() {
        let mut runtime = PluginRuntime::new().unwrap();

        // Define a plugin in the runtime
        let plugin_code = r#"
        var plugin = {
            name: "test-plugin",
            matchPatterns: ["*.s3.amazonaws.com", "s3.amazonaws.com"],
            credentialSchema: ["access_key", "secret_key"],
            transform: function(request, credentials) {
                request.headers["Authorization"] = "AWS4-HMAC-SHA256 ...";
                return request;
            }
        };
        "#;

        runtime.execute(plugin_code).unwrap();
        let plugin = runtime.extract_plugin_metadata("test-plugin").unwrap();

        assert_eq!(plugin.name, "test-plugin");
        assert_eq!(plugin.match_patterns, vec!["*.s3.amazonaws.com", "s3.amazonaws.com"]);
        assert_eq!(plugin.credential_schema, vec!["access_key", "secret_key"]);
    }

    #[test]
    fn test_extract_plugin_metadata_name_mismatch() {
        let mut runtime = PluginRuntime::new().unwrap();

        let plugin_code = r#"
        var plugin = {
            name: "actual-name",
            matchPatterns: [],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        runtime.execute(plugin_code).unwrap();
        let result = runtime.extract_plugin_metadata("expected-name");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("name mismatch"));
    }

    #[test]
    fn test_execute_transform_basic() {
        let mut runtime = PluginRuntime::new().unwrap();

        // Load a plugin that adds a header
        let plugin_code = r#"
        var plugin = {
            name: "test-plugin",
            matchPatterns: ["api.example.com"],
            credentialSchema: ["api_key"],
            transform: function(request, credentials) {
                request.headers["X-API-Key"] = credentials.api_key;
                return request;
            }
        };
        "#;

        runtime.execute(plugin_code).unwrap();
        let plugin = runtime.extract_plugin_metadata("test-plugin").unwrap();
        // Manually cache the plugin since we didn't use load_plugin
        runtime.plugins.insert(plugin.name.clone(), plugin);

        let request = ACPRequest::new("GET", "https://api.example.com/users")
            .with_header("Content-Type", "application/json");

        let mut credentials = ACPCredentials::new();
        credentials.set("api_key", "secret123");

        let transformed = runtime.execute_transform("test-plugin", request, &credentials).unwrap();

        assert_eq!(transformed.method, "GET");
        assert_eq!(transformed.url, "https://api.example.com/users");
        assert_eq!(transformed.get_header("Content-Type"), Some(&"application/json".to_string()));
        assert_eq!(transformed.get_header("X-API-Key"), Some(&"secret123".to_string()));
    }

    #[test]
    fn test_execute_transform_modifies_request() {
        let mut runtime = PluginRuntime::new().unwrap();

        // Plugin that modifies method and URL
        let plugin_code = r#"
        var plugin = {
            name: "rewriter",
            matchPatterns: ["old.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) {
                request.method = "POST";
                request.url = request.url.replace("old.example.com", "new.example.com");
                return request;
            }
        };
        "#;

        runtime.execute(plugin_code).unwrap();
        let plugin = runtime.extract_plugin_metadata("rewriter").unwrap();
        runtime.plugins.insert(plugin.name.clone(), plugin);

        let request = ACPRequest::new("GET", "https://old.example.com/api");

        let transformed = runtime.execute_transform("rewriter", request, &ACPCredentials::new()).unwrap();

        assert_eq!(transformed.method, "POST");
        assert_eq!(transformed.url, "https://new.example.com/api");
    }

    #[test]
    fn test_execute_transform_with_body() {
        let mut runtime = PluginRuntime::new().unwrap();

        // Plugin that modifies the body
        let plugin_code = r#"
        var plugin = {
            name: "body-transformer",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) {
                // Convert body to string, modify it, convert back
                var decoder = new TextDecoder();
                var encoder = new TextEncoder();
                var bodyStr = decoder.decode(request.body);
                var modified = bodyStr + " - transformed";
                request.body = encoder.encode(modified);
                return request;
            }
        };
        "#;

        runtime.execute(plugin_code).unwrap();
        let plugin = runtime.extract_plugin_metadata("body-transformer").unwrap();
        runtime.plugins.insert(plugin.name.clone(), plugin);

        let request = ACPRequest::new("POST", "https://api.example.com/data")
            .with_body(b"original".to_vec());

        let transformed = runtime.execute_transform("body-transformer", request, &ACPCredentials::new()).unwrap();

        assert_eq!(transformed.body, b"original - transformed");
    }

    #[test]
    fn test_execute_transform_plugin_not_loaded() {
        let mut runtime = PluginRuntime::new().unwrap();

        let request = ACPRequest::new("GET", "https://api.example.com");
        let result = runtime.execute_transform("nonexistent", request, &ACPCredentials::new());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not loaded"));
    }

    #[test]
    fn test_request_to_js_and_back() {
        let mut runtime = PluginRuntime::new().unwrap();

        let original = ACPRequest::new("POST", "https://api.example.com/test")
            .with_header("Content-Type", "application/json")
            .with_header("Authorization", "Bearer token123")
            .with_body(b"test body".to_vec());

        let js_value = runtime.request_to_js(&original).unwrap();
        let roundtrip = runtime.js_to_request(&js_value).unwrap();

        assert_eq!(original.method, roundtrip.method);
        assert_eq!(original.url, roundtrip.url);
        assert_eq!(original.headers, roundtrip.headers);
        assert_eq!(original.body, roundtrip.body);
    }

    #[test]
    fn test_credentials_to_js() {
        let mut runtime = PluginRuntime::new().unwrap();

        let mut credentials = ACPCredentials::new();
        credentials.set("api_key", "secret123");
        credentials.set("region", "us-west-2");

        let js_value = runtime.credentials_to_js(&credentials).unwrap();

        // Verify we can access the credentials in JS
        runtime.context.register_global_property(
            JsString::from("testCreds"),
            js_value,
            boa_engine::property::Attribute::all()
        ).unwrap();

        let result = runtime.execute("testCreds.api_key").unwrap();
        assert_eq!(result.as_string().unwrap().to_std_string_escaped(), "secret123");

        let result2 = runtime.execute("testCreds.region").unwrap();
        assert_eq!(result2.as_string().unwrap().to_std_string_escaped(), "us-west-2");
    }

    // Tests for ACP.log function
    #[test]
    fn test_acp_log_exists() {
        let mut runtime = PluginRuntime::new().unwrap();
        assert!(runtime.execute("typeof ACP.log").unwrap().as_string().unwrap().to_std_string_escaped() == "function");
    }

    #[test]
    fn test_acp_log_captures_messages() {
        let mut runtime = PluginRuntime::new().unwrap();
        runtime.execute("ACP.log('hello')").unwrap();
        runtime.execute("ACP.log('world')").unwrap();

        let logs = runtime.get_logs();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0], "hello");
        assert_eq!(logs[1], "world");
    }

    #[test]
    fn test_acp_log_clear() {
        let mut runtime = PluginRuntime::new().unwrap();
        runtime.execute("ACP.log('test1')").unwrap();
        runtime.execute("ACP.log('test2')").unwrap();

        assert_eq!(runtime.get_logs().len(), 2);

        runtime.clear_logs();
        assert_eq!(runtime.get_logs().len(), 0);
    }

    #[test]
    fn test_acp_log_converts_types() {
        let mut runtime = PluginRuntime::new().unwrap();
        runtime.execute("ACP.log(123)").unwrap();
        runtime.execute("ACP.log(true)").unwrap();
        runtime.execute("ACP.log({key: 'value'})").unwrap();

        let logs = runtime.get_logs();
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0], "123");
        assert_eq!(logs[1], "true");
        assert!(logs[2].contains("key"));
    }

    // Tests for URL APIs
    #[test]
    fn test_url_exists() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("typeof URL").unwrap();
        assert_eq!(result.as_string().unwrap().to_std_string_escaped(), "function");
    }

    #[test]
    fn test_url_parsing() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute(r#"
            var url = new URL('https://example.com:8080/path?key=value#hash');
            JSON.stringify({
                protocol: url.protocol,
                hostname: url.hostname,
                port: url.port,
                pathname: url.pathname,
                search: url.search,
                hash: url.hash
            });
        "#).unwrap();

        let json_str = result.as_string().unwrap().to_std_string_escaped();
        assert!(json_str.contains("\"protocol\":\"https:\""));
        assert!(json_str.contains("\"hostname\":\"example.com\""));
        assert!(json_str.contains("\"port\":\"8080\""));
        assert!(json_str.contains("\"pathname\":\"/path\""));
        assert!(json_str.contains("\"search\":\"?key=value\""));
        assert!(json_str.contains("\"hash\":\"#hash\""));
    }

    #[test]
    fn test_url_search_params_exists() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute("typeof URLSearchParams").unwrap();
        assert_eq!(result.as_string().unwrap().to_std_string_escaped(), "function");
    }

    #[test]
    fn test_url_search_params_basic() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute(r#"
            var params = new URLSearchParams('key1=value1&key2=value2');
            params.get('key1');
        "#).unwrap();

        assert_eq!(result.as_string().unwrap().to_std_string_escaped(), "value1");
    }

    #[test]
    fn test_url_search_params_set() {
        let mut runtime = PluginRuntime::new().unwrap();
        let result = runtime.execute(r#"
            var params = new URLSearchParams();
            params.set('foo', 'bar');
            params.toString();
        "#).unwrap();

        assert_eq!(result.as_string().unwrap().to_std_string_escaped(), "foo=bar");
    }

    // Tests for timeout wrapper
    #[tokio::test]
    async fn test_execute_transform_with_timeout_success() {
        use std::time::Duration;

        let mut runtime = PluginRuntime::new().unwrap();

        // Load a fast plugin
        let plugin_code = r#"
        var plugin = {
            name: "fast-plugin",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) {
                request.headers["X-Fast"] = "true";
                return request;
            }
        };
        "#;

        runtime.execute(plugin_code).unwrap();
        let plugin = runtime.extract_plugin_metadata("fast-plugin").unwrap();
        runtime.plugins.insert(plugin.name.clone(), plugin);

        let request = ACPRequest::new("GET", "https://api.example.com/test");

        let result = runtime.execute_transform_with_timeout(
            "fast-plugin",
            request,
            &ACPCredentials::new(),
            Duration::from_secs(5)
        ).await;

        assert!(result.is_ok());
        let transformed = result.unwrap();
        assert_eq!(transformed.get_header("X-Fast"), Some(&"true".to_string()));
    }

    #[tokio::test]
    async fn test_execute_transform_with_timeout_slow_operation() {
        use std::time::Duration;

        let mut runtime = PluginRuntime::new().unwrap();

        // Load a slow plugin (using busy loop)
        let plugin_code = r#"
        var plugin = {
            name: "slow-plugin",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) {
                // Busy loop for a while
                var start = ACP.util.now();
                while (ACP.util.now() - start < 100) {
                    // Spin
                }
                request.headers["X-Slow"] = "true";
                return request;
            }
        };
        "#;

        runtime.execute(plugin_code).unwrap();
        let plugin = runtime.extract_plugin_metadata("slow-plugin").unwrap();
        runtime.plugins.insert(plugin.name.clone(), plugin);

        let request = ACPRequest::new("GET", "https://api.example.com/test");

        // Use a very short timeout to catch the slow operation
        let result = runtime.execute_transform_with_timeout(
            "slow-plugin",
            request,
            &ACPCredentials::new(),
            Duration::from_millis(10)
        ).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("timeout") || err.to_string().contains("Timeout"));
    }
}
