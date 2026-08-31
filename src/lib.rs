// `no_main` is skipped under `cfg(test)` so `cargo test --lib` can link its
// own generated test-harness `main`; the wasm build (which never sets
// `cfg(test)`) still gets `no_main` as required by the Extism PDK.
#![cfg_attr(not(test), no_main)]

//! `s11auth` — out-of-tree `sso`-flavor wasm auth plugin, ABI v1. Ports the
//! Python `s11auth` keystoneauth1 plugin (OIDC-via-Keycloak browser auth
//! against Keystone) to `gtema/openstack`'s wasm plugin ABI. See
//! `docs/superpowers/specs/2026-08-13-s11auth-wasm-plugin-design.md` in the
//! `gtema/openstack` repo (<https://github.com/gtema/openstack>) for the full
//! design.

use extism_pdk::*;
use serde_json::{json, Value};

#[host_fn]
extern "ExtismHost" {
    fn identity_http_request(request: String) -> String;
    fn idp_http_request(request: String) -> String;
}

#[plugin_fn]
pub fn plugin_abi_version(_input: String) -> FnResult<String> {
    Ok("1".to_string())
}

#[plugin_fn]
pub fn auth_supported_methods(_input: String) -> FnResult<String> {
    Ok(json!(["s11auth"]).to_string())
}

#[plugin_fn]
pub fn auth_api_version(_input: String) -> FnResult<String> {
    Ok(json!([3, 0]).to_string())
}

fn requirements_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "oidc_endpoint": {
                "type": "string",
                "description": "OIDC issuer base endpoint",
                "default": "https://idp.apis.syseleven.de/realms/application/protocol/openid-connect"
            },
            "client_id": {
                "type": "string",
                "description": "OIDC client id registered with the IdP",
                "default": "s11-user"
            },
            "callback_port": {
                "type": ["string", "integer"],
                "description": "Fixed local callback port; must match the IdP's redirect_uri allowlist. \
                    If unset, the host binds an ephemeral port. No JSON Schema `default` is declared \
                    here because the actual default behavior (an ephemeral port) isn't a fixed value \
                    the host merges into `values` — a user must set this explicitly in their cloud \
                    config for a fixed port to take effect."
            }
        }
    })
}

#[plugin_fn]
pub fn auth_requirements(_hints: String) -> FnResult<String> {
    Ok(requirements_schema().to_string())
}

const DEFAULT_OIDC_ENDPOINT: &str =
    "https://idp.apis.syseleven.de/realms/application/protocol/openid-connect";
const DEFAULT_CLIENT_ID: &str = "s11-user";

pub(crate) fn resolve_oidc_config(values: &Value) -> (String, String) {
    let oidc_endpoint = values
        .get("oidc_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_OIDC_ENDPOINT)
        .to_string();
    let client_id = values
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_CLIENT_ID)
        .to_string();
    (oidc_endpoint, client_id)
}

/// Build the IdP authorize URL from `oidc_endpoint` + the PKCE/nonce
/// parameters, using proper URL joining/encoding rather than string
/// concatenation. This correctly handles an `oidc_endpoint` with a trailing
/// slash (no doubled `//`) and one that already carries a query string
/// (dropped, rather than producing a malformed URL with two `?`s).
pub(crate) fn build_authorize_url(
    oidc_endpoint: &str,
    client_id: &str,
    callback_url: &str,
    code_challenge: &str,
    nonce: &str,
) -> Result<String, String> {
    let mut url =
        url::Url::parse(oidc_endpoint).map_err(|e| format!("invalid oidc_endpoint: {e}"))?;
    url.set_query(None);
    url.set_fragment(None);
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| "oidc_endpoint cannot be a base URL".to_string())?;
        // Drop a trailing empty segment (from a trailing `/`) so `auth` is
        // appended as a sibling of the last real segment, not nested under
        // an empty one, and so a non-trailing-slash endpoint doesn't have
        // its last segment overwritten either way.
        segments.pop_if_empty();
        segments.push("auth");
    }
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", callback_url)
        .append_pair("response_type", "code")
        .append_pair("response_mode", "form_post")
        .append_pair("scope", "openid")
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("nonce", nonce);
    Ok(url.to_string())
}

#[plugin_fn]
pub fn sso_build_request(input: String) -> FnResult<String> {
    let request: Value = serde_json::from_str(&input)?;
    let callback_url = request
        .get("callback_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let code_challenge = request
        .get("code_challenge")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let nonce = request
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let identity_url = request
        .get("identity_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let values = request.get("values").cloned().unwrap_or(json!({}));
    let scope = request.get("scope").cloned().unwrap_or(Value::Null);

    let (oidc_endpoint, client_id) = resolve_oidc_config(&values);

    let parsed = url::Url::parse(callback_url)
        .map_err(|e| Error::msg(format!("invalid callback_url: {e}")))?;
    let redirect_host = match parsed.port() {
        Some(port) => format!("{}:{port}", parsed.host_str().unwrap_or("")),
        None => parsed.host_str().unwrap_or("").to_string(),
    };

    let authorize_url = build_authorize_url(
        &oidc_endpoint,
        &client_id,
        callback_url,
        code_challenge,
        nonce,
    )
    .map_err(Error::msg)?;

    // None of these six are secret; stashed so `sso_parse_callback` (whose
    // input carries only `{params, code_verifier}`, no config passthrough)
    // can remember its own configuration, the nonce to compare against, and
    // the full scope (only ever delivered here, in the build request) —
    // stashed verbatim (as its JSON text) rather than picked apart, so any
    // scope shape (project by id/name+domain, domain, system, "unscoped")
    // survives untouched through to the Keystone auth body.
    var::set("oidc_endpoint", oidc_endpoint.as_str())?;
    var::set("client_id", client_id.as_str())?;
    var::set("callback_url", callback_url)?;
    var::set("nonce", nonce)?;
    var::set("scope", scope.to_string())?;
    var::set("identity_url", identity_url)?;

    Ok(json!({"url": authorize_url, "redirect_host": redirect_host}).to_string())
}

/// Derive the Keystone `/auth/tokens` path to send to `identity_http_request`
/// from the `identity_url` of the build request.
///
/// The host strips `identity_url` down to its origin (scheme+host+port) and
/// joins the guest's `path` against that, so a bare `/auth/tokens` would drop
/// the version prefix (e.g. `/v3`) the identity endpoint carries and 404. We
/// recover that prefix here; a bare-origin `identity_url` falls back to `/v3`.
pub(crate) fn auth_tokens_path(identity_url: &str) -> String {
    let prefix = url::Url::parse(identity_url)
        .map(|u| u.path().trim_end_matches('/').to_string())
        .unwrap_or_default();
    let prefix = if prefix.is_empty() { "/v3" } else { &prefix };
    format!("{prefix}/auth/tokens")
}

/// Derive the token-exchange path to send to `idp_http_request` from the
/// configured `oidc_endpoint`.
///
/// The host binds `idp_origin` by stripping the *path* off the authorize
/// URL's origin (see `identity_origin` in `gtema/openstack`'s
/// `sdk/plugin-wasm/src/plugin.rs`, and `resolve_request` in `host.rs`,
/// which joins the guest's `path` against that stripped origin). So a
/// hardcoded `"/token"` path would resolve against the *origin*, dropping
/// whatever path prefix (e.g. `/realms/application/protocol/openid-connect`)
/// the OIDC endpoint carries. We recover that prefix here.
pub(crate) fn token_exchange_path(oidc_endpoint: &str) -> String {
    url::Url::parse(oidc_endpoint)
        .map(|u| format!("{}/token", u.path().trim_end_matches('/')))
        .unwrap_or_else(|_| "/token".to_string())
}

pub(crate) fn decode_jwt_payload(jwt: &str) -> Result<Value, Error> {
    use base64::Engine as _;
    let payload_segment = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::msg("jwt did not have a payload segment"))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_segment)?;
    Ok(serde_json::from_slice(&decoded)?)
}

/// Truncate a response body to a short excerpt suitable for appending to an
/// error message, so a real debugging session gets something actionable
/// instead of a bare status code.
fn error_body_excerpt(body_str: &str) -> String {
    let trimmed = body_str.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    const MAX_LEN: usize = 200;
    let excerpt: String = trimmed.chars().take(MAX_LEN).collect();
    if trimmed.chars().count() > MAX_LEN {
        format!(": {excerpt}...")
    } else {
        format!(": {excerpt}")
    }
}

pub(crate) fn extract_id_token(status: u16, body_str: &str) -> Result<String, String> {
    if !(200..300).contains(&status) {
        return Err(format!(
            "token endpoint returned status {status}{}",
            error_body_excerpt(body_str)
        ));
    }
    let body: Value = serde_json::from_str(body_str)
        .map_err(|e| format!("token endpoint returned invalid JSON: {e}"))?;
    let id_token = body
        .get("id_token")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if id_token.is_empty() {
        return Err("token endpoint response did not include id_token".to_string());
    }
    Ok(id_token.to_string())
}

pub(crate) fn check_nonce(claims: &Value, expected_nonce: &str) -> Result<(), String> {
    if expected_nonce.is_empty() {
        return Err(
            "no nonce was stashed from sso_build_request; refusing to validate id_token"
                .to_string(),
        );
    }
    let got_nonce = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if got_nonce != expected_nonce {
        return Err("id_token nonce did not match".to_string());
    }
    Ok(())
}

/// Build the Keystone `/auth/tokens` request body. `scope`, when present, is
/// the verbatim value stashed by `sso_build_request` — passed through as-is
/// so any scope shape Keystone accepts (`project` by id or by name+domain,
/// `domain`, `system`) survives untouched. The literal string `"unscoped"`
/// (keystoneauth1's convention for "no scope") is special-cased to omit the
/// `scope` key entirely, matching what Keystone expects for an unscoped
/// request.
pub(crate) fn build_keystone_auth_body(id_token: &str, scope: Option<&Value>) -> Value {
    let mut auth = json!({
        "identity": {
            "methods": ["s11auth"],
            "s11auth": {"token": id_token}
        }
    });
    if let Some(scope) = scope {
        if scope.as_str() != Some("unscoped") {
            auth["scope"] = scope.clone();
        }
    }
    json!({"auth": auth})
}

/// Parse the `scope` value stashed by `sso_build_request` (its JSON text,
/// via `var::get("scope")`) back into a `Value` for `build_keystone_auth_body`.
/// An empty stash (nothing was ever set) or a stashed literal `null` (the
/// build request's `scope` was absent/null) both mean "no scope" — `None`.
pub(crate) fn parse_stashed_scope(stashed_scope: &str) -> Option<Value> {
    if stashed_scope.is_empty() {
        None
    } else {
        serde_json::from_str::<Value>(stashed_scope).ok()
    }
    .filter(|v| !v.is_null())
}

pub(crate) fn extract_keystone_token(
    status: u16,
    headers: &std::collections::BTreeMap<String, String>,
    body_str: &str,
) -> Result<String, String> {
    if !(200..300).contains(&status) {
        return Err(format!(
            "identity endpoint returned status {status}{}",
            error_body_excerpt(body_str)
        ));
    }
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-subject-token"))
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            "identity endpoint response did not include token via X-Subject-Token header"
                .to_string()
        })
}

/// The host's `AuthResultMsg { auth_info: Option<AuthResponse> }` requires
/// `AuthResponse.token` to be a fully-formed `TokenInfo` (non-optional
/// fields such as `expires_at`, `user`). Passing a malformed body through
/// (e.g. `{}`) would make the host's deserialization hard-fail, whereas
/// `auth_info: null` just makes the host treat the token as
/// `AuthState::Unset` — uncached, but not a hard failure. So only emit the
/// parsed Keystone response when it actually looks like a token response
/// (has a top-level `token` object); otherwise fall back to `null`.
pub(crate) fn parse_auth_info(identity_body: &str) -> Option<Value> {
    serde_json::from_str::<Value>(identity_body)
        .ok()
        .filter(|parsed| parsed.get("token").is_some())
}

/// With `response_mode=form_post`, a cancelled/denied authorization POSTs
/// `error`/`error_description` and no `code` at all. This extracts that
/// error message from the callback `params`, so the caller can surface it
/// directly rather than attempting a code exchange with an empty code. An
/// empty `error=` value (the host delivers params as a
/// `BTreeMap<String, String>`, so a bare `error=` yields `Some("")`) is
/// treated as "no error param present" rather than a blank error message.
pub(crate) fn extract_idp_error(params: &Value) -> Option<String> {
    let idp_error = params
        .get("error")
        .and_then(|v| v.as_str())
        .filter(|e| !e.is_empty())?;
    let message = params
        .get("error_description")
        .and_then(|v| v.as_str())
        .filter(|e| !e.is_empty())
        .unwrap_or(idp_error);
    Some(message.to_string())
}

#[plugin_fn]
pub fn sso_parse_callback(input: String) -> FnResult<String> {
    let request: Value = serde_json::from_str(&input)?;
    let params = request.get("params").cloned().unwrap_or(json!({}));
    let code_verifier = request
        .get("code_verifier")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if let Some(message) = extract_idp_error(&params) {
        return Ok(json!({"error": message}).to_string());
    }

    let code = params
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if code.is_empty() {
        return Ok(json!({"error": "callback did not include an authorization code"}).to_string());
    }

    let oidc_endpoint: String = var::get("oidc_endpoint")?.unwrap_or_default();
    let client_id: String = var::get("client_id")?.unwrap_or_default();
    let callback_url: String = var::get("callback_url")?.unwrap_or_default();
    let expected_nonce: String = var::get("nonce")?.unwrap_or_default();
    let stashed_scope: String = var::get("scope")?.unwrap_or_default();
    let identity_url: String = var::get("identity_url")?.unwrap_or_default();

    // If `sso_build_request` never ran on this plugin instance (or the host
    // never persisted its vars across the two calls), every one of the
    // stashed values above is empty, and falling through would attempt a
    // token exchange against a bogus/empty `oidc_endpoint` with empty
    // `client_id`/`callback_url` — an obscure failure at the IdP instead of
    // a clear one here. `oidc_endpoint` is the simplest reliable signal.
    if oidc_endpoint.is_empty() {
        return Ok(json!({
            "error": "no stashed sso state; sso_build_request must be called before sso_parse_callback"
        })
        .to_string());
    }

    let form_body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", &client_id)
        .append_pair("code", code)
        .append_pair("redirect_uri", &callback_url)
        .append_pair("code_verifier", code_verifier)
        .finish();

    let http_request = json!({
        "method": "POST",
        "path": token_exchange_path(&oidc_endpoint),
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": form_body,
    })
    .to_string();
    // Match rather than `?` so a guest-catchable failure from this host
    // import (e.g. the host returning bytes `String::from_bytes` rejects)
    // becomes a normal `{"error": ...}` guest response instead of
    // propagating out of `sso_parse_callback` as a plugin-fault `Err`.
    //
    // Caveat verified against `send_and_shape_response` in the real host's
    // `sdk/plugin-wasm/src/host.rs`: an actual host-function-level failure
    // (unreachable IdP, DNS failure, timeout — cases where `.send()` itself
    // errors) makes the *host_fn's Rust closure* return `Err`, which the
    // Extism/Wasmtime host-function-call boundary turns into a genuine wasm
    // trap. That trap unwinds the guest call stack immediately — this
    // `match` (and any other guest-side code) never regains control to
    // format a response, and the failure still surfaces to
    // `gtema/openstack`'s `plugin.rs` caller as a plugin-fault
    // `WasmPluginError`, not a clean `AuthResultMsg::Error`. This `match`
    // only helps for failures that stay within the guest's own control flow.
    let response_json = match unsafe { idp_http_request(http_request) } {
        Ok(r) => r,
        Err(e) => {
            return Ok(json!({"error": format!("idp token request failed: {e}")}).to_string());
        }
    };
    let response: Value = serde_json::from_str(&response_json)?;
    let status = response.get("status").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let body = response
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let id_token = match extract_id_token(status, body) {
        Ok(t) => t,
        Err(e) => return Ok(json!({"error": e}).to_string()),
    };

    let claims = match decode_jwt_payload(&id_token) {
        Ok(c) => c,
        Err(e) => return Ok(json!({"error": format!("invalid id_token: {e}")}).to_string()),
    };
    if let Err(e) = check_nonce(&claims, &expected_nonce) {
        return Ok(json!({"error": e}).to_string());
    }

    let scope_value = parse_stashed_scope(&stashed_scope);
    let auth_body = build_keystone_auth_body(&id_token, scope_value.as_ref());

    let identity_request = json!({
        "method": "POST",
        "path": auth_tokens_path(&identity_url),
        "headers": {"Content-Type": "application/json"},
        "body": auth_body.to_string(),
    })
    .to_string();
    // Same rationale (and same caveat) as the `idp_http_request` match above.
    let identity_response_json = match unsafe { identity_http_request(identity_request) } {
        Ok(r) => r,
        Err(e) => {
            return Ok(json!({"error": format!("identity request failed: {e}")}).to_string());
        }
    };
    let identity_response: Value = serde_json::from_str(&identity_response_json)?;
    let identity_status = identity_response
        .get("status")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;
    let identity_headers: std::collections::BTreeMap<String, String> = identity_response
        .get("headers")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let identity_body = identity_response
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    match extract_keystone_token(identity_status, &identity_headers, identity_body) {
        Ok(token) => {
            // The host's `AuthResponse` deserializes directly from this raw
            // Keystone `/auth/tokens` response body — an `auth_info: null`
            // here makes the host treat the token as `AuthState::Unset`, so
            // the session cache immediately drops it and every `osc`
            // invocation re-triggers a full browser SSO round trip. Parse
            // and pass the body through so the host can cache a real token
            // (see `parse_auth_info` for why malformed bodies fall back to
            // `null` instead of being passed through).
            let auth_info = parse_auth_info(identity_body);
            Ok(json!({"ok": {"token": token, "auth_info": auth_info}}).to_string())
        }
        Err(e) => Ok(json!({"error": e}).to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_schema_declares_all_three_fields_as_optional() {
        let schema = requirements_schema();
        assert_eq!(schema["type"], "object");
        let props = schema["properties"].as_object().expect("properties object");
        assert!(props.contains_key("oidc_endpoint"));
        assert!(props.contains_key("client_id"));
        assert!(props.contains_key("callback_port"));
        // All fields optional per spec: no "required" array, or an empty one.
        assert!(
            schema.get("required").is_none()
                || schema["required"]
                    .as_array()
                    .map(|a| a.is_empty())
                    .unwrap_or(false)
        );
    }

    #[test]
    fn resolve_oidc_config_applies_defaults_when_values_absent() {
        let (endpoint, client_id) = resolve_oidc_config(&json!({}));
        assert_eq!(
            endpoint,
            "https://idp.apis.syseleven.de/realms/application/protocol/openid-connect"
        );
        assert_eq!(client_id, "s11-user");
    }

    #[test]
    fn resolve_oidc_config_honors_overrides() {
        let (endpoint, client_id) = resolve_oidc_config(&json!({
            "oidc_endpoint": "https://idp.example.test/realms/x/protocol/openid-connect",
            "client_id": "custom-client"
        }));
        assert_eq!(
            endpoint,
            "https://idp.example.test/realms/x/protocol/openid-connect"
        );
        assert_eq!(client_id, "custom-client");
    }

    #[test]
    fn build_authorize_url_embeds_pkce_and_nonce_and_callback() {
        let url = build_authorize_url(
            "https://idp.example.test/realms/x/protocol/openid-connect",
            "s11-user",
            "http://127.0.0.1:8080/callback?state=abc123",
            "challenge-value",
            "nonce-value",
        )
        .unwrap();
        assert!(url.starts_with("https://idp.example.test/realms/x/protocol/openid-connect/auth?"));
        assert!(url.contains("client_id=s11-user"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("response_mode=form_post"));
        assert!(url.contains("scope=openid"));
        assert!(url.contains("code_challenge=challenge-value"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("nonce=nonce-value"));
        assert!(url.contains(
            &url::form_urlencoded::byte_serialize(b"http://127.0.0.1:8080/callback?state=abc123")
                .collect::<String>()
        ));
    }

    #[test]
    fn build_authorize_url_percent_encodes_client_id() {
        let url = build_authorize_url(
            "https://idp.example.test/realms/x/protocol/openid-connect",
            "client with spaces&more",
            "http://127.0.0.1:8080/callback",
            "challenge-value",
            "nonce-value",
        )
        .unwrap();
        assert!(!url.contains("client_id=client with spaces&more"));
        assert!(url.contains(&format!(
            "client_id={}",
            url::form_urlencoded::byte_serialize(b"client with spaces&more").collect::<String>()
        )));
    }

    #[test]
    fn build_authorize_url_handles_trailing_slash_without_doubled_slash() {
        let url = build_authorize_url(
            "https://idp.example.test/realms/x/protocol/openid-connect/",
            "s11-user",
            "http://127.0.0.1:8080/callback",
            "challenge-value",
            "nonce-value",
        )
        .unwrap();
        assert!(
            url.starts_with("https://idp.example.test/realms/x/protocol/openid-connect/auth?"),
            "unexpected doubled slash or malformed path: {url}"
        );
        assert!(!url.contains("//auth"));
    }

    #[test]
    fn build_authorize_url_drops_existing_query_string_on_oidc_endpoint() {
        let url = build_authorize_url(
            "https://idp.example.test/realms/x/protocol/openid-connect?foo=bar",
            "s11-user",
            "http://127.0.0.1:8080/callback",
            "challenge-value",
            "nonce-value",
        )
        .unwrap();
        assert!(
            url.starts_with("https://idp.example.test/realms/x/protocol/openid-connect/auth?"),
            "unexpected malformed url: {url}"
        );
        // Only one `?` — no leftover `foo=bar` from the endpoint's own query.
        assert_eq!(url.matches('?').count(), 1);
        assert!(!url.contains("foo=bar"));
    }

    #[test]
    fn auth_tokens_path_keeps_identity_url_version_prefix() {
        assert_eq!(
            auth_tokens_path("https://keystone.example.test/v3"),
            "/v3/auth/tokens"
        );
        assert_eq!(
            auth_tokens_path("https://keystone.example.test/identity/v3/"),
            "/identity/v3/auth/tokens"
        );
    }

    #[test]
    fn auth_tokens_path_defaults_to_v3_for_bare_origin() {
        assert_eq!(
            auth_tokens_path("https://keystone.example.test"),
            "/v3/auth/tokens"
        );
        assert_eq!(auth_tokens_path(""), "/v3/auth/tokens");
    }

    #[test]
    fn token_exchange_path_derives_from_oidc_endpoint_path() {
        assert_eq!(
            token_exchange_path(
                "https://idp.apis.syseleven.de/realms/application/protocol/openid-connect"
            ),
            "/realms/application/protocol/openid-connect/token"
        );
    }

    #[test]
    fn token_exchange_path_handles_bare_origin_with_no_path() {
        assert_eq!(token_exchange_path("https://idp.example.test"), "/token");
    }

    #[test]
    fn decode_jwt_payload_reads_middle_segment() {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"nonce": "abc"}).to_string());
        let jwt = format!("header.{payload}.sig");
        let claims = decode_jwt_payload(&jwt).unwrap();
        assert_eq!(claims["nonce"], "abc");
    }

    #[test]
    fn decode_jwt_payload_rejects_malformed_jwt() {
        assert!(decode_jwt_payload("not-a-jwt").is_err());
    }

    #[test]
    fn extract_id_token_rejects_non_2xx_status() {
        let err = extract_id_token(500, r#"{"id_token": "x"}"#).unwrap_err();
        assert!(err.contains("500"));
    }

    #[test]
    fn extract_id_token_rejects_missing_id_token() {
        let err = extract_id_token(200, r#"{"access_token": "x"}"#).unwrap_err();
        assert!(err.contains("id_token"));
    }

    #[test]
    fn extract_id_token_returns_value_on_success() {
        let token = extract_id_token(200, r#"{"id_token": "the-id-token"}"#).unwrap();
        assert_eq!(token, "the-id-token");
    }

    #[test]
    fn check_nonce_rejects_mismatch() {
        let err = check_nonce(&json!({"nonce": "got"}), "expected").unwrap_err();
        assert!(err.contains("nonce"));
    }

    #[test]
    fn check_nonce_accepts_match() {
        assert!(check_nonce(&json!({"nonce": "same"}), "same").is_ok());
    }

    #[test]
    fn check_nonce_rejects_when_expected_nonce_is_empty() {
        // No nonce was ever stashed (e.g. `var::get` returned `None`); an
        // id_token whose `nonce` claim is also absent/empty must not be
        // treated as a match just because both sides default to "".
        let err = check_nonce(&json!({}), "").unwrap_err();
        assert!(err.contains("nonce"));
    }

    #[test]
    fn extract_idp_error_returns_none_when_absent() {
        assert_eq!(extract_idp_error(&json!({"code": "abc"})), None);
    }

    #[test]
    fn extract_idp_error_treats_empty_error_as_absent() {
        // The host delivers params as a `BTreeMap<String, String>`, so a
        // bare `error=` in the query string yields `Some("")`, not absence.
        assert_eq!(extract_idp_error(&json!({"error": ""})), None);
    }

    #[test]
    fn extract_idp_error_prefers_description_over_bare_code() {
        let msg = extract_idp_error(&json!({
            "error": "access_denied",
            "error_description": "user cancelled login"
        }));
        assert_eq!(msg, Some("user cancelled login".to_string()));
    }

    #[test]
    fn extract_idp_error_falls_back_to_bare_code_when_description_empty() {
        let msg = extract_idp_error(&json!({"error": "access_denied", "error_description": ""}));
        assert_eq!(msg, Some("access_denied".to_string()));
    }

    #[test]
    fn parse_stashed_scope_treats_empty_string_as_none() {
        assert_eq!(parse_stashed_scope(""), None);
    }

    #[test]
    fn parse_stashed_scope_treats_stashed_null_as_none() {
        assert_eq!(parse_stashed_scope("null"), None);
    }

    #[test]
    fn parse_stashed_scope_round_trips_project_name_and_domain_scope() {
        let scope = json!({"project": {"name": "myproject", "domain": {"name": "mydomain"}}});
        assert_eq!(parse_stashed_scope(&scope.to_string()), Some(scope));
    }

    #[test]
    fn parse_stashed_scope_round_trips_unscoped_string() {
        assert_eq!(parse_stashed_scope("\"unscoped\""), Some(json!("unscoped")));
    }

    #[test]
    fn build_keystone_auth_body_without_scope() {
        let body = build_keystone_auth_body("the-id-token", None);
        assert_eq!(body["auth"]["identity"]["methods"], json!(["s11auth"]));
        assert_eq!(body["auth"]["identity"]["s11auth"]["token"], "the-id-token");
        assert!(body["auth"].get("scope").is_none());
    }

    #[test]
    fn build_keystone_auth_body_with_project_id_scope() {
        let scope = json!({"project": {"id": "proj-123"}});
        let body = build_keystone_auth_body("the-id-token", Some(&scope));
        assert_eq!(body["auth"]["scope"]["project"]["id"], "proj-123");
    }

    #[test]
    fn build_keystone_auth_body_with_project_name_and_domain_scope() {
        // `--os-project-name` + domain: a shape the prior `project.id`-only
        // stash silently dropped. Must pass through verbatim.
        let scope = json!({"project": {"name": "myproject", "domain": {"name": "mydomain"}}});
        let body = build_keystone_auth_body("the-id-token", Some(&scope));
        assert_eq!(body["auth"]["scope"], scope);
    }

    #[test]
    fn build_keystone_auth_body_with_domain_scope() {
        let scope = json!({"domain": {"id": "dom-123"}});
        let body = build_keystone_auth_body("the-id-token", Some(&scope));
        assert_eq!(body["auth"]["scope"], scope);
    }

    #[test]
    fn build_keystone_auth_body_with_system_scope() {
        let scope = json!({"system": {"all": true}});
        let body = build_keystone_auth_body("the-id-token", Some(&scope));
        assert_eq!(body["auth"]["scope"], scope);
    }

    #[test]
    fn build_keystone_auth_body_omits_scope_key_for_unscoped_string() {
        // keystoneauth1 convention: the literal string "unscoped" means "no
        // scope", not a scope value to send verbatim.
        let scope = json!("unscoped");
        let body = build_keystone_auth_body("the-id-token", Some(&scope));
        assert!(body["auth"].get("scope").is_none());
    }

    #[test]
    fn extract_keystone_token_rejects_non_2xx_status() {
        let headers = std::collections::BTreeMap::new();
        let err = extract_keystone_token(401, &headers, "").unwrap_err();
        assert!(err.contains("401"));
    }

    #[test]
    fn extract_keystone_token_rejects_missing_header() {
        let headers = std::collections::BTreeMap::new();
        let err = extract_keystone_token(201, &headers, "").unwrap_err();
        assert!(err.contains("token"));
    }

    #[test]
    fn extract_keystone_token_is_header_case_insensitive() {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert(
            "x-subject-token".to_string(),
            "keystone-token-value".to_string(),
        );
        let token = extract_keystone_token(201, &headers, "").unwrap();
        assert_eq!(token, "keystone-token-value");
    }

    #[test]
    fn extract_keystone_token_includes_body_excerpt_on_error() {
        let headers = std::collections::BTreeMap::new();
        let err = extract_keystone_token(
            401,
            &headers,
            r#"{"error": {"message": "invalid token provided"}}"#,
        )
        .unwrap_err();
        assert!(err.contains("401"));
        assert!(err.contains("invalid token provided"));
    }

    #[test]
    fn extract_id_token_includes_body_excerpt_on_error() {
        let err = extract_id_token(
            400,
            r#"{"error":"invalid_grant","error_description":"Code not valid"}"#,
        )
        .unwrap_err();
        assert!(err.contains("400"));
        assert!(err.contains("Code not valid"));
    }

    #[test]
    fn parse_auth_info_passes_through_well_formed_token_response() {
        let body =
            r#"{"token":{"expires_at":"2026-08-17T00:00:00.000000Z","user":{"id":"user-123"}}}"#;
        let auth_info = parse_auth_info(body).expect("well-formed body should be passed through");
        assert_eq!(auth_info["token"]["user"]["id"], "user-123");
    }

    #[test]
    fn parse_auth_info_falls_back_to_null_for_malformed_body() {
        assert_eq!(parse_auth_info("{}"), None);
        assert_eq!(parse_auth_info(""), None);
        assert_eq!(parse_auth_info(r#"{"not_token": true}"#), None);
    }
}
