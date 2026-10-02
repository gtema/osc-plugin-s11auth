use std::collections::BTreeMap;

use extism::{Function, Manifest, Plugin, UserData, ValType, Wasm};
use httpmock::prelude::*;
use serde::{Deserialize, Serialize};

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/wasm32-unknown-unknown/release/s11auth_wasm_plugin.wasm")
}

#[derive(Debug, Deserialize)]
struct HttpRequestMsg {
    method: String,
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Debug, Serialize)]
struct HttpResponseMsg {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

// NOTE (fidelity gap): this is a bare `format!("{base}{path}")` join, not a
// replica of the host's actual origin-join + same-origin-check logic
// (`resolve_request` in `gtema/openstack`'s `sdk/plugin-wasm/src/host.rs`),
// and this harness never calls the host's `validate_sso_build_response`
// (which requires an `https` scheme and an exact `redirect_host` match on
// the authorize URL before ever handing it to a browser). A guest-built
// path/URL that the real host would reject on those grounds can still pass
// here — don't treat these integration tests as a full simulation of host
// validation.
fn proxy_to(base_url: &str, request: &str) -> Result<String, extism::Error> {
    let req: HttpRequestMsg = serde_json::from_str(request)
        .map_err(|e| extism::Error::msg(format!("invalid request payload: {e}")))?;
    let client = reqwest::blocking::Client::new();
    let url = format!("{}{}", base_url.trim_end_matches('/'), req.path);
    let method = reqwest::Method::from_bytes(req.method.as_bytes())
        .map_err(|e| extism::Error::msg(format!("invalid method: {e}")))?;
    let mut builder = client.request(method, url);
    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    let resp = builder
        .send()
        .map_err(|e| extism::Error::msg(format!("request failed: {e}")))?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect();
    let body = resp
        .text()
        .map_err(|e| extism::Error::msg(format!("reading response body failed: {e}")))?;
    Ok(serde_json::to_string(&HttpResponseMsg {
        status,
        headers,
        body,
    })?)
}

extism::host_fn!(idp_http_request(ctx: String; request: String) -> String {
    let base = ctx.get()?;
    let base = base.lock().map_err(|_| extism::Error::msg("idp base url lock poisoned"))?;
    proxy_to(&base, &request)
});

extism::host_fn!(identity_http_request(ctx: String; request: String) -> String {
    let base = ctx.get()?;
    let base = base.lock().map_err(|_| extism::Error::msg("identity base url lock poisoned"))?;
    proxy_to(&base, &request)
});

fn raw_plugin(
    idp_base_url: &str,
    identity_base_url: &str,
) -> Result<Plugin, Box<dyn std::error::Error>> {
    // `disallow_all_hosts` only restricts sockets the *wasm guest* could open
    // directly (it has none); the host_fn shims above run outside the guest
    // sandbox and reach the mock servers over a normal `reqwest::blocking`
    // client, same as `host.rs`'s real `identity_http_request`/
    // `idp_http_request` do.
    let manifest = Manifest::new([Wasm::file(fixture_path())]).disallow_all_hosts();
    let functions = vec![
        Function::new(
            "identity_http_request",
            [ValType::I64],
            [ValType::I64],
            UserData::new(identity_base_url.to_string()),
            identity_http_request,
        ),
        Function::new(
            "idp_http_request",
            [ValType::I64],
            [ValType::I64],
            UserData::new(idp_base_url.to_string()),
            idp_http_request,
        ),
    ];
    Ok(Plugin::new(manifest, functions, false)?)
}

/// SHA256(code_verifier), base64url-no-pad — mirrors what a real IdP does to
/// verify a PKCE `code_verifier` against the `code_challenge` it saw earlier,
/// so this test can independently confirm the plugin's callback path really
/// forwards the verifier it was handed.
fn pkce_challenge_for(code_verifier: &str) -> String {
    use base64::Engine as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, code_verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

// Minimal local mirror of the host's `AuthResponse`/`TokenInfo` shape (see
// `sdk/auth-core/src/types.rs` in the sibling `gtema/openstack` repo) — just
// enough to assert that the plugin's `auth_info` output round-trips through
// the fields the host actually requires as non-optional: `token.expires_at`
// and `token.user.{id,name}`. Not a dependency on the real host crate, and
// not exhaustive of every optional field on the real types.
#[derive(Debug, Deserialize)]
struct LocalAuthResponse {
    token: LocalTokenInfo,
}

#[derive(Debug, Deserialize)]
struct LocalTokenInfo {
    expires_at: String,
    user: LocalUser,
}

#[derive(Debug, Deserialize)]
struct LocalUser {
    id: String,
    name: String,
}

/// A realistic Keystone `/auth/tokens` response body, including all fields
/// the host's `TokenInfo` requires as non-optional (`expires_at`, and
/// `user.{id,name}`) plus a couple of the commonly-present optional ones
/// (`issued_at`, `project`) for realism.
fn realistic_keystone_body() -> serde_json::Value {
    serde_json::json!({
        "token": {
            "issued_at": "2026-08-17T09:00:00.000000Z",
            "expires_at": "2026-08-17T10:00:00.000000Z",
            "user": {
                "id": "user-123",
                "name": "alice",
                "domain": {"id": "default", "name": "Default"},
            },
            "project": {
                "id": "proj-123",
                "name": "myproject",
                "domain": {"id": "default", "name": "Default"},
            },
            "roles": [{"id": "role-1", "name": "member"}],
            "catalog": [],
        }
    })
}

fn make_id_token(nonce: &str) -> String {
    use base64::Engine as _;
    let encode = |v: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let header = encode(&serde_json::json!({"alg": "none", "typ": "JWT"}));
    let payload = encode(&serde_json::json!({"nonce": nonce}));
    format!("{header}.{payload}.")
}

#[test]
fn sso_round_trip_exchanges_code_and_returns_keystone_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();

    let code_verifier = "test-code-verifier-0123456789";
    let code_challenge = pkce_challenge_for(code_verifier);
    let nonce = "test-nonce-value";
    let id_token = make_id_token(nonce);

    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    // Mount the mock IdP under a path prefix (mirroring a real OIDC
    // endpoint like `.../realms/application/protocol/openid-connect`) so
    // this test catches a regression to a hardcoded `/token` path, which
    // would silently work when the mock server has no path prefix at all.
    let oidc_endpoint = format!(
        "{}/realms/test/protocol/openid-connect",
        idp_server.base_url()
    );

    let build_request = serde_json::json!({
        "identity_url": format!("{}/v3", identity_server.base_url()),
        "callback_url": "http://127.0.0.1:8080/callback?state=abc123",
        "values": {"oidc_endpoint": oidc_endpoint},
        "scope": null,
        "hints": null,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    })
    .to_string();
    let build_output: String = plugin.call("sso_build_request", build_request.as_str())?;
    let build: serde_json::Value = serde_json::from_str(&build_output)?;
    let authorize_url = build["url"].as_str().ok_or("missing url")?;
    assert!(authorize_url.starts_with(&format!("{oidc_endpoint}/auth?")));
    assert!(authorize_url.contains(&format!("code_challenge={code_challenge}")));
    assert!(authorize_url.contains(&format!("nonce={nonce}")));
    assert_eq!(build["redirect_host"].as_str(), Some("127.0.0.1:8080"));

    let idp_mock = idp_server.mock(|when, then| {
        when.method(POST)
            .path("/realms/test/protocol/openid-connect/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body_includes("grant_type=authorization_code")
            .body_includes(format!("code_verifier={code_verifier}"));
        then.status(200)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"id_token": id_token}).to_string());
    });
    let keystone_body = realistic_keystone_body();
    let identity_mock = identity_server.mock(|when, then| {
        when.method(POST).path("/v3/auth/tokens");
        then.status(201)
            .header("X-Subject-Token", "keystone-token-value")
            .header("Content-Type", "application/json")
            .body(keystone_body.to_string());
    });

    let callback_request = serde_json::json!({
        "params": {"code": "raw-code-from-callback"},
        "code_verifier": code_verifier,
    })
    .to_string();
    let callback_output: String = plugin.call("sso_parse_callback", callback_request.as_str())?;
    let callback: serde_json::Value = serde_json::from_str(&callback_output)?;

    idp_mock.assert();
    identity_mock.assert();
    assert_eq!(
        callback["ok"]["token"].as_str(),
        Some("keystone-token-value")
    );
    // Important #1 regression check: the raw Keystone `/auth/tokens` body
    // must be parsed through as `auth_info`, not left `null` — the host's
    // `AuthResponse` deserializes directly from it, and a `null` here makes
    // the host drop the token from its session cache immediately.
    assert_eq!(callback["ok"]["auth_info"], keystone_body);
    // Confirm the passed-through `auth_info` actually deserializes into the
    // shape the host's `AuthResponse`/`TokenInfo` require (non-optional
    // `expires_at`, `user.id`, `user.name`) rather than merely matching the
    // fixture value byte-for-byte.
    let auth_info_str = callback["ok"]["auth_info"].to_string();
    let parsed: LocalAuthResponse = serde_json::from_str(&auth_info_str)?;
    assert_eq!(parsed.token.user.id, "user-123");
    assert_eq!(parsed.token.user.name, "alice");
    assert_eq!(parsed.token.expires_at, "2026-08-17T10:00:00.000000Z");
    Ok(())
}

// No integration test for "idp/identity host-import failure surfaces as a
// guest `{"error": ...}` response" (Minor #3 in the final review): verified
// empirically (a `host_fn!` closure returning `Err`, wired the same way as
// this crate's own `raw_plugin` helper and as the real host's
// `send_and_shape_response` in `sdk/plugin-wasm/src/host.rs`) that a host
// import returning `Err` produces an actual Wasmtime trap that unwinds the
// guest call stack immediately — `plugin.call()` itself returns `Err`, and
// no guest-side code (including the `match` this fix added in
// `sso_parse_callback`, replacing a bare `?`) ever regains control to format
// a `{"error": ...}` response. That match still converts any *guest-catchable*
// failure from these two host imports (e.g. non-UTF8 response bytes) into a
// clean guest response instead of an unnecessary `?`-propagated fault, but it
// cannot and does not change what happens for a network-level IdP/identity
// failure — that remains a plugin-fault `WasmPluginError` at the
// `gtema/openstack` `plugin.rs` caller, by construction of the Extism host
// function ABI, not something fixable from this plugin's guest code.

#[test]
fn sso_round_trip_callback_without_prior_build_reports_missing_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();
    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    // No `sso_build_request` call on this plugin instance — `oidc_endpoint`
    // (and everything else) is unstashed.
    let callback_request = serde_json::json!({
        "params": {"code": "raw-code-from-callback"},
        "code_verifier": "verifier",
    })
    .to_string();
    let callback_output: String = plugin.call("sso_parse_callback", callback_request.as_str())?;
    let callback: serde_json::Value = serde_json::from_str(&callback_output)?;

    let error = callback
        .get("error")
        .and_then(|v| v.as_str())
        .ok_or("expected missing stashed state to surface as a guest-level error")?;
    assert!(
        error.contains("sso_build_request"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn sso_round_trip_reports_nonce_mismatch_as_guest_error() -> Result<(), Box<dyn std::error::Error>>
{
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();

    let code_verifier = "test-code-verifier-0123456789";
    let code_challenge = pkce_challenge_for(code_verifier);
    let id_token_with_wrong_nonce = make_id_token("a-completely-different-nonce");

    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    let build_request = serde_json::json!({
        "identity_url": format!("{}/v3", identity_server.base_url()),
        "callback_url": "http://127.0.0.1:8080/callback?state=abc123",
        "values": {},
        "scope": null,
        "hints": null,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": "expected-nonce",
    })
    .to_string();
    plugin.call::<&str, String>("sso_build_request", &build_request)?;

    idp_server.mock(|when, then| {
        when.method(POST)
            .path("/realms/application/protocol/openid-connect/token");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"id_token": id_token_with_wrong_nonce}).to_string());
    });

    let callback_request = serde_json::json!({
        "params": {"code": "raw-code-from-callback"},
        "code_verifier": code_verifier,
    })
    .to_string();
    let callback_output: String = plugin.call("sso_parse_callback", callback_request.as_str())?;
    let callback: serde_json::Value = serde_json::from_str(&callback_output)?;

    let error = callback
        .get("error")
        .and_then(|v| v.as_str())
        .ok_or("expected a mismatched nonce to surface as a guest-level error")?;
    assert!(error.contains("nonce"), "unexpected error: {error}");
    Ok(())
}

#[test]
fn sso_round_trip_includes_project_scope_when_configured() -> Result<(), Box<dyn std::error::Error>>
{
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();

    let code_verifier = "test-code-verifier-0123456789";
    let code_challenge = pkce_challenge_for(code_verifier);
    let nonce = "test-nonce-value";
    let id_token = make_id_token(nonce);

    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    let build_request = serde_json::json!({
        "identity_url": format!("{}/v3", identity_server.base_url()),
        "callback_url": "http://127.0.0.1:8080/callback?state=abc123",
        "values": {},
        "scope": {"project": {"id": "proj-123"}},
        "hints": null,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    })
    .to_string();
    plugin.call::<&str, String>("sso_build_request", &build_request)?;

    idp_server.mock(|when, then| {
        when.method(POST)
            .path("/realms/application/protocol/openid-connect/token");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"id_token": id_token}).to_string());
    });
    let identity_mock = identity_server.mock(|when, then| {
        when.method(POST)
            .path("/v3/auth/tokens")
            .json_body_includes(r#"{"auth": {"scope": {"project": {"id": "proj-123"}}}}"#);
        then.status(201)
            .header("X-Subject-Token", "scoped-token-value")
            .header("Content-Type", "application/json")
            .body("{}");
    });

    // `scope` is only ever delivered in the *build* request per the real
    // host's `SsoCallbackMsg` shape (`{params, code_verifier}`, no `scope`
    // field) — it must already have taken effect via `sso_build_request`
    // above, stashed host-plugin-side, not re-supplied here.
    let callback_request = serde_json::json!({
        "params": {"code": "raw-code-from-callback"},
        "code_verifier": code_verifier,
    })
    .to_string();
    let callback_output: String = plugin.call("sso_parse_callback", callback_request.as_str())?;
    let callback: serde_json::Value = serde_json::from_str(&callback_output)?;

    identity_mock.assert();
    assert_eq!(callback["ok"]["token"].as_str(), Some("scoped-token-value"));
    Ok(())
}

#[test]
fn sso_round_trip_passes_through_project_name_and_domain_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    // Important #2 regression check: a user authenticating with
    // `--os-project-name` + domain sends a scope shape the old
    // `scope.project.id`-only stash silently dropped. It must now pass
    // through verbatim.
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();

    let code_verifier = "test-code-verifier-0123456789";
    let code_challenge = pkce_challenge_for(code_verifier);
    let nonce = "test-nonce-value";
    let id_token = make_id_token(nonce);

    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    let build_request = serde_json::json!({
        "identity_url": format!("{}/v3", identity_server.base_url()),
        "callback_url": "http://127.0.0.1:8080/callback?state=abc123",
        "values": {},
        "scope": {"project": {"name": "myproject", "domain": {"name": "mydomain"}}},
        "hints": null,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    })
    .to_string();
    plugin.call::<&str, String>("sso_build_request", &build_request)?;

    idp_server.mock(|when, then| {
        when.method(POST)
            .path("/realms/application/protocol/openid-connect/token");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"id_token": id_token}).to_string());
    });
    let identity_mock = identity_server.mock(|when, then| {
        when.method(POST)
            .path("/v3/auth/tokens")
            .json_body_includes(
                r#"{"auth": {"scope": {"project": {"domain": {"name": "mydomain"}, "name": "myproject"}}}}"#,
            );
        then.status(201)
            .header("X-Subject-Token", "scoped-token-value")
            .header("Content-Type", "application/json")
            .body("{}");
    });

    let callback_request = serde_json::json!({
        "params": {"code": "raw-code-from-callback"},
        "code_verifier": code_verifier,
    })
    .to_string();
    let callback_output: String = plugin.call("sso_parse_callback", callback_request.as_str())?;
    let callback: serde_json::Value = serde_json::from_str(&callback_output)?;

    identity_mock.assert();
    assert_eq!(callback["ok"]["token"].as_str(), Some("scoped-token-value"));
    Ok(())
}

#[test]
fn sso_round_trip_unscoped_string_omits_scope_key() -> Result<(), Box<dyn std::error::Error>> {
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();

    let code_verifier = "test-code-verifier-0123456789";
    let code_challenge = pkce_challenge_for(code_verifier);
    let nonce = "test-nonce-value";
    let id_token = make_id_token(nonce);

    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    let build_request = serde_json::json!({
        "identity_url": format!("{}/v3", identity_server.base_url()),
        "callback_url": "http://127.0.0.1:8080/callback?state=abc123",
        "values": {},
        "scope": "unscoped",
        "hints": null,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    })
    .to_string();
    plugin.call::<&str, String>("sso_build_request", &build_request)?;

    idp_server.mock(|when, then| {
        when.method(POST)
            .path("/realms/application/protocol/openid-connect/token");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"id_token": id_token}).to_string());
    });
    let identity_mock = identity_server.mock(|when, then| {
        when.method(POST).path("/v3/auth/tokens").is_true(|req| {
            let parsed: serde_json::Value =
                serde_json::from_str(&req.body_string()).unwrap_or_default();
            parsed["auth"].get("scope").is_none()
        });
        then.status(201)
            .header("X-Subject-Token", "unscoped-token-value")
            .header("Content-Type", "application/json")
            .body("{}");
    });

    let callback_request = serde_json::json!({
        "params": {"code": "raw-code-from-callback"},
        "code_verifier": code_verifier,
    })
    .to_string();
    let callback_output: String = plugin.call("sso_parse_callback", callback_request.as_str())?;
    let callback: serde_json::Value = serde_json::from_str(&callback_output)?;

    identity_mock.assert();
    assert_eq!(
        callback["ok"]["token"].as_str(),
        Some("unscoped-token-value")
    );
    Ok(())
}

#[test]
fn sso_round_trip_callback_without_code_reports_error() -> Result<(), Box<dyn std::error::Error>> {
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();
    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    let callback_request = serde_json::json!({
        "params": {},
        "code_verifier": "verifier",
    })
    .to_string();
    let callback_output: String = plugin.call("sso_parse_callback", callback_request.as_str())?;
    let callback: serde_json::Value = serde_json::from_str(&callback_output)?;

    let error = callback
        .get("error")
        .and_then(|v| v.as_str())
        .ok_or("expected missing code to surface as a guest-level error")?;
    assert!(error.contains("code"), "unexpected error: {error}");
    Ok(())
}
