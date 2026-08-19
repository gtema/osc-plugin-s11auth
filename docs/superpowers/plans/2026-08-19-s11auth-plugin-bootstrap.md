# s11auth wasm plugin bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap the standalone `osc-auth-s11` repo into a working `sso`-flavor wasm auth plugin (`auth_type` name `s11auth`) conforming to `gtema/openstack`'s plugin ABI v1, per the design at `gtema/openstack/docs/superpowers/specs/2026-08-13-s11auth-wasm-plugin-design.md`.

**Architecture:** Single `cdylib` crate, `#![no_main]`, built with `extism-pdk`. Each export is a thin `#[plugin_fn]` wrapper around pure, natively-testable helper functions — the wrappers themselves (which touch Extism's `var_set`/`var_get`/host imports) can only be exercised by loading the compiled `.wasm` into a real `extism::Plugin`, so those get integration tests instead of unit tests. Structurally mirrors `gtema/openstack`'s `sdk/plugin-wasm/fixtures/example-sso-plugin` fixture, which is the reference implementation of this exact ABI.

**Tech Stack:** Rust 2021, `extism-pdk` 1.4 (guest), `extism` ^1.30 (host, dev-only for tests), `httpmock` ^0.8 + `reqwest` (blocking) for the integration-test mock IdP/identity servers, target `wasm32-unknown-unknown`.

## Global Constraints

- `auth_type` name is exactly `s11auth` (drop-in replacement for the Python original — not a rename).
- Crate is fully standalone: `[workspace]` empty table in `Cargo.toml` (opts out of any parent workspace), flat `[dependencies]` table — no workspace-inheritance style (`dep.workspace = true`), since there is no parent workspace here.
- Every guest export returns `Ok(...)` with a JSON string; failure paths are `{"error": "..."}`, never a Rust-level `Err` from a `#[plugin_fn]` under normal operation (per spec's "Error handling" section).
- No `id_token` JWS signature verification (out of scope, matches PKCE/nonce specs' stance — the channel is already origin-pinned/SSRF-checked host-side).
- No plugin-side `state` generation, no `project_id` regex validation, no plugin-side JWT disk cache — all explicitly dropped per spec.
- Target triple: `wasm32-unknown-unknown` (no WASI syscalls needed — only Extism host imports are used).

---

### Task 1: Repo scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`
- Create: `.gitignore`
- Create: `LICENSE`
- Create: `README.md`

**Interfaces:**
- Produces: crate name `s11auth-wasm-plugin`, lib target `s11auth_wasm_plugin`, builds to `target/wasm32-unknown-unknown/release/s11auth_wasm_plugin.wasm`. All later tasks build on this file's `use` statements and export list.

- [ ] **Step 1: Write `Cargo.toml`**

```toml
[workspace]

[package]
name = "s11auth-wasm-plugin"
description = "s11auth out-of-tree wasm auth plugin (OIDC-via-Keycloak SSO against Keystone), ABI v1"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
extism-pdk = "1.4"
serde_json = "1"
url = "2"
base64 = "0.22"

[dev-dependencies]
extism = "^1.30"
httpmock = "^0.8"
reqwest = { version = "^0.13", default-features = false, features = ["rustls-tls", "blocking", "json"] }
serde = { version = "^1.0", features = ["derive"] }
ring = "^0.17"
```

- [ ] **Step 2: Write `.gitignore`**

```
/target
```

- [ ] **Step 3: Write `LICENSE`**

Standard Apache License 2.0 full text (matches `gtema/openstack`'s own license, and the `license = "Apache-2.0"` field above).

- [ ] **Step 4: Write `README.md`**

```markdown
# s11auth wasm plugin

Out-of-tree `sso`-flavor wasm auth plugin implementing `s11auth` (OIDC-via-Keycloak
browser auth against Keystone), conforming to `gtema/openstack`'s plugin ABI v1.
Drop-in replacement for the Python `s11auth` keystoneauth1 plugin.

## Build

    cargo build --target wasm32-unknown-unknown --release

## Test

Unit tests run natively:

    cargo test --lib

Integration tests load the compiled `.wasm` into a real `extism::Plugin`, so build
it first:

    cargo build --target wasm32-unknown-unknown --release
    cargo test --test sso_round_trip
```

- [ ] **Step 5: Write `src/lib.rs` skeleton**

```rust
#![no_main]

//! `s11auth` — out-of-tree `sso`-flavor wasm auth plugin, ABI v1. Ports the
//! Python `s11auth` keystoneauth1 plugin (OIDC-via-Keycloak browser auth
//! against Keystone) to `gtema/openstack`'s wasm plugin ABI. See
//! `docs/superpowers/specs/2026-08-13-s11auth-wasm-plugin-design.md` in the
//! `gtema/openstack` repo for the full design.

use extism_pdk::*;
use serde_json::{Value, json};

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
```

- [ ] **Step 6: Verify it builds**

Run: `cargo build --target wasm32-unknown-unknown --release`
Expected: builds cleanly, produces `target/wasm32-unknown-unknown/release/s11auth_wasm_plugin.wasm` (`auth_requirements`/`sso_build_request`/`sso_parse_callback` added in later tasks — this step only proves the skeleton + host imports + three trivial exports compile).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml .gitignore LICENSE README.md src/lib.rs
git commit -m "chore: scaffold s11auth wasm plugin crate"
```

---

### Task 2: `auth_requirements`

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub(crate) fn requirements_schema() -> Value`, used only inside this task's own `#[plugin_fn] auth_requirements`.

- [ ] **Step 1: Write the failing test**

Add to `src/lib.rs`:

```rust
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
        assert!(props.contains_key("redirect_port"));
        // All fields optional per spec: no "required" array, or an empty one.
        assert!(
            schema.get("required").is_none()
                || schema["required"].as_array().map(|a| a.is_empty()).unwrap_or(false)
        );
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib requirements_schema_declares_all_three_fields_as_optional`
Expected: FAIL with `cannot find function 'requirements_schema'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/lib.rs` (above the `#[cfg(test)]` module):

```rust
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
            "redirect_port": {
                "type": ["string", "integer"],
                "description": "Fixed local callback port; must match the IdP's redirect_uri allowlist",
                "default": 8080
            }
        }
    })
}

#[plugin_fn]
pub fn auth_requirements(_hints: String) -> FnResult<String> {
    Ok(requirements_schema().to_string())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib requirements_schema_declares_all_three_fields_as_optional`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs
git commit -m "feat: implement auth_requirements"
```

---

### Task 3: `sso_build_request` pure helpers

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub(crate) fn resolve_oidc_config(values: &Value) -> (String, String)` (returns `(oidc_endpoint, client_id)`, applying spec defaults), `pub(crate) fn build_authorize_url(oidc_endpoint: &str, client_id: &str, callback_url: &str, code_challenge: &str, nonce: &str) -> String`. Both consumed by Task 4's `sso_build_request` wrapper.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
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
        assert_eq!(endpoint, "https://idp.example.test/realms/x/protocol/openid-connect");
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
        );
        assert!(url.starts_with(
            "https://idp.example.test/realms/x/protocol/openid-connect/auth?"
        ));
        assert!(url.contains("client_id=s11-user"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("response_mode=form_post"));
        assert!(url.contains("scope=openid"));
        assert!(url.contains("code_challenge=challenge-value"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("nonce=nonce-value"));
        assert!(url.contains(&url::form_urlencoded::byte_serialize(
            b"http://127.0.0.1:8080/callback?state=abc123"
        ).collect::<String>()));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib resolve_oidc_config_ build_authorize_url_`
Expected: FAIL with `cannot find function` errors

- [ ] **Step 3: Write minimal implementation**

Add to `src/lib.rs`:

```rust
const DEFAULT_OIDC_ENDPOINT: &str =
    "https://idp.apis.syseleven.de/realms/application/protocol/openid-connect";
const DEFAULT_CLIENT_ID: &str = "s11-user";

fn resolve_oidc_config(values: &Value) -> (String, String) {
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

fn build_authorize_url(
    oidc_endpoint: &str,
    client_id: &str,
    callback_url: &str,
    code_challenge: &str,
    nonce: &str,
) -> String {
    let encoded_redirect: String =
        url::form_urlencoded::byte_serialize(callback_url.as_bytes()).collect();
    format!(
        "{oidc_endpoint}/auth?client_id={client_id}&redirect_uri={encoded_redirect}\
         &response_type=code&response_mode=form_post&scope=openid\
         &code_challenge={code_challenge}&code_challenge_method=S256&nonce={nonce}"
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib resolve_oidc_config_ build_authorize_url_`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs
git commit -m "feat: add sso_build_request pure helpers"
```

---

### Task 4: `sso_build_request` plugin export

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `resolve_oidc_config`, `build_authorize_url` (Task 3).
- Produces: `#[plugin_fn] sso_build_request`. Stashes `oidc_endpoint`/`client_id`/`callback_url`/`nonce` via `var::set` for Task 6 to read back via `var::get`.

No native unit test is possible here: `var::set` and the Extism guest runtime it depends on only exist once this crate is compiled to wasm and loaded by a real `extism::Plugin` — attempting to call it from a `cargo test --lib` run panics (no host bound). This export is validated end-to-end by Task 7's integration test instead.

- [ ] **Step 1: Implement**

Add to `src/lib.rs`:

```rust
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
    let values = request.get("values").cloned().unwrap_or(json!({}));

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
    );

    // None of these four are secret; stashed so `sso_parse_callback` (whose
    // input carries only `{params, code_verifier}`, no config passthrough)
    // can remember its own configuration and the nonce to compare against.
    var::set("oidc_endpoint", oidc_endpoint.as_str())?;
    var::set("client_id", client_id.as_str())?;
    var::set("callback_url", callback_url)?;
    var::set("nonce", nonce)?;

    Ok(json!({"url": authorize_url, "redirect_host": redirect_host}).to_string())
}
```

- [ ] **Step 2: Confirm it compiles**

Run: `cargo build --target wasm32-unknown-unknown --release`
Expected: builds cleanly

- [ ] **Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "feat: implement sso_build_request"
```

---

### Task 5: `sso_parse_callback` pure helpers

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `pub(crate) fn decode_jwt_payload(jwt: &str) -> Result<Value, Error>`
  - `pub(crate) fn extract_id_token(status: u16, body_str: &str) -> Result<String, String>`
  - `pub(crate) fn check_nonce(claims: &Value, expected_nonce: &str) -> Result<(), String>`
  - `pub(crate) fn build_keystone_auth_body(id_token: &str, project_id: Option<&str>) -> Value`
  - `pub(crate) fn extract_keystone_token(status: u16, headers: &std::collections::BTreeMap<String, String>) -> Result<String, String>`

  All consumed by Task 6's `sso_parse_callback` wrapper.

  `extract_keystone_token` reads the `X-Subject-Token` response header (case-insensitively), matching Keystone's real `/auth/tokens` contract — not a JSON body field. This is a deliberate correctness fix over the `example-sso-plugin` fixture's simplified body-based token extraction, which only exists because that fixture talks to a fake test identity endpoint, not real Keystone.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
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
    fn build_keystone_auth_body_without_project_scope() {
        let body = build_keystone_auth_body("the-id-token", None);
        assert_eq!(body["auth"]["identity"]["methods"], json!(["s11auth"]));
        assert_eq!(body["auth"]["identity"]["s11auth"]["token"], "the-id-token");
        assert!(body["auth"].get("scope").is_none());
    }

    #[test]
    fn build_keystone_auth_body_with_project_scope() {
        let body = build_keystone_auth_body("the-id-token", Some("proj-123"));
        assert_eq!(body["auth"]["scope"]["project"]["id"], "proj-123");
    }

    #[test]
    fn extract_keystone_token_rejects_non_2xx_status() {
        let headers = std::collections::BTreeMap::new();
        let err = extract_keystone_token(401, &headers).unwrap_err();
        assert!(err.contains("401"));
    }

    #[test]
    fn extract_keystone_token_rejects_missing_header() {
        let headers = std::collections::BTreeMap::new();
        let err = extract_keystone_token(201, &headers).unwrap_err();
        assert!(err.contains("token"));
    }

    #[test]
    fn extract_keystone_token_is_header_case_insensitive() {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("x-subject-token".to_string(), "keystone-token-value".to_string());
        let token = extract_keystone_token(201, &headers).unwrap();
        assert_eq!(token, "keystone-token-value");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib decode_jwt_payload_ extract_id_token_ check_nonce_ build_keystone_auth_body_ extract_keystone_token_`
Expected: FAIL with `cannot find function` errors

- [ ] **Step 3: Write minimal implementation**

Add to `src/lib.rs`:

```rust
fn decode_jwt_payload(jwt: &str) -> Result<Value, Error> {
    use base64::Engine as _;
    let payload_segment = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::msg("jwt did not have a payload segment"))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_segment)?;
    Ok(serde_json::from_slice(&decoded)?)
}

fn extract_id_token(status: u16, body_str: &str) -> Result<String, String> {
    if !(200..300).contains(&status) {
        return Err(format!("token endpoint returned status {status}"));
    }
    let body: Value = serde_json::from_str(body_str)
        .map_err(|e| format!("token endpoint returned invalid JSON: {e}"))?;
    let id_token = body.get("id_token").and_then(|v| v.as_str()).unwrap_or_default();
    if id_token.is_empty() {
        return Err("token endpoint response did not include id_token".to_string());
    }
    Ok(id_token.to_string())
}

fn check_nonce(claims: &Value, expected_nonce: &str) -> Result<(), String> {
    let got_nonce = claims.get("nonce").and_then(|v| v.as_str()).unwrap_or_default();
    if got_nonce != expected_nonce {
        return Err("id_token nonce did not match".to_string());
    }
    Ok(())
}

fn build_keystone_auth_body(id_token: &str, project_id: Option<&str>) -> Value {
    let mut auth = json!({
        "identity": {
            "methods": ["s11auth"],
            "s11auth": {"token": id_token}
        }
    });
    if let Some(project_id) = project_id {
        auth["scope"] = json!({"project": {"id": project_id}});
    }
    json!({"auth": auth})
}

fn extract_keystone_token(
    status: u16,
    headers: &std::collections::BTreeMap<String, String>,
) -> Result<String, String> {
    if !(200..300).contains(&status) {
        return Err(format!("identity endpoint returned status {status}"));
    }
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-subject-token"))
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "identity endpoint response did not include an X-Subject-Token header".to_string())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib decode_jwt_payload_ extract_id_token_ check_nonce_ build_keystone_auth_body_ extract_keystone_token_`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs
git commit -m "feat: add sso_parse_callback pure helpers"
```

---

### Task 6: `sso_parse_callback` plugin export

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: all five helpers from Task 5, plus `var::get` for the four values Task 4 stashed.
- Produces: `#[plugin_fn] sso_parse_callback`.

Like Task 4, this wrapper touches `var::get` and the two host-fn imports, so it can't run under `cargo test --lib`. Validated by Task 7/8's integration tests.

- [ ] **Step 1: Implement**

Add to `src/lib.rs`:

```rust
#[plugin_fn]
pub fn sso_parse_callback(input: String) -> FnResult<String> {
    let request: Value = serde_json::from_str(&input)?;
    let params = request.get("params").cloned().unwrap_or(json!({}));
    let code_verifier = request
        .get("code_verifier")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let code = params.get("code").and_then(|v| v.as_str()).unwrap_or_default();

    let oidc_endpoint: String = var::get("oidc_endpoint")?.unwrap_or_default();
    let client_id: String = var::get("client_id")?.unwrap_or_default();
    let callback_url: String = var::get("callback_url")?.unwrap_or_default();
    let expected_nonce: String = var::get("nonce")?.unwrap_or_default();

    let form_body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", &client_id)
        .append_pair("code", code)
        .append_pair("redirect_uri", &callback_url)
        .append_pair("code_verifier", code_verifier)
        .finish();

    let http_request = json!({
        "method": "POST",
        "path": "/token",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": form_body,
    })
    .to_string();
    let response_json = unsafe { idp_http_request(http_request)? };
    let response: Value = serde_json::from_str(&response_json)?;
    let status = response.get("status").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let body = response.get("body").and_then(|v| v.as_str()).unwrap_or_default();

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

    let project_id = request
        .get("scope")
        .and_then(|s| s.get("project"))
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_str());
    let auth_body = build_keystone_auth_body(&id_token, project_id);

    let identity_request = json!({
        "method": "POST",
        "path": "/auth/tokens",
        "headers": {"Content-Type": "application/json"},
        "body": auth_body.to_string(),
    })
    .to_string();
    let identity_response_json = unsafe { identity_http_request(identity_request)? };
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

    match extract_keystone_token(identity_status, &identity_headers) {
        Ok(token) => Ok(json!({"ok": {"token": token, "auth_info": null}}).to_string()),
        Err(e) => Ok(json!({"error": e}).to_string()),
    }
}
```

Note the request's `oidc_endpoint`/`token` path is joined by the host against the bound IdP origin (per ABI: guest supplies a request-relative `path`, host resolves it) — so the POST path here is `/token`, relative, exactly like `identity_http_request`'s `/auth/tokens` is relative to the identity origin. This matches `host.rs`'s `resolve_request`, which rejects any `path` that doesn't start with `/`.

- [ ] **Step 2: Confirm it compiles**

Run: `cargo build --target wasm32-unknown-unknown --release`
Expected: builds cleanly

- [ ] **Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "feat: implement sso_parse_callback"
```

---

### Task 7: Integration test harness + happy-path round trip

**Files:**
- Create: `tests/sso_round_trip.rs`

**Interfaces:**
- Consumes: the compiled `target/wasm32-unknown-unknown/release/s11auth_wasm_plugin.wasm` (built by Task 1/4/6's `cargo build` steps — this test does not build it itself).
- Produces: `fn raw_plugin(idp_base_url: &str, identity_base_url: &str) -> extism::Plugin`, reused by Task 8.

- [ ] **Step 1: Write the test file**

```rust
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

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
    Ok(serde_json::to_string(&HttpResponseMsg { status, headers, body })?)
}

extism::host_fn!(idp_http_request(ctx: Arc<Mutex<String>>; request: String) -> String {
    let base = ctx.get()?;
    let base = base.lock().map_err(|_| extism::Error::msg("idp base url lock poisoned"))?;
    proxy_to(&base, &request)
});

extism::host_fn!(identity_http_request(ctx: Arc<Mutex<String>>; request: String) -> String {
    let base = ctx.get()?;
    let base = base.lock().map_err(|_| extism::Error::msg("identity base url lock poisoned"))?;
    proxy_to(&base, &request)
});

fn raw_plugin(idp_base_url: &str, identity_base_url: &str) -> Result<Plugin, Box<dyn std::error::Error>> {
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
            UserData::new(Arc::new(Mutex::new(identity_base_url.to_string()))),
            identity_http_request,
        ),
        Function::new(
            "idp_http_request",
            [ValType::I64],
            [ValType::I64],
            UserData::new(Arc::new(Mutex::new(idp_base_url.to_string()))),
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
fn sso_round_trip_exchanges_code_and_returns_keystone_token() -> Result<(), Box<dyn std::error::Error>> {
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();

    let code_verifier = "test-code-verifier-0123456789";
    let code_challenge = pkce_challenge_for(code_verifier);
    let nonce = "test-nonce-value";
    let id_token = make_id_token(nonce);

    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    let build_request = serde_json::json!({
        "identity_url": identity_server.base_url(),
        "callback_url": "http://127.0.0.1:8080/callback?state=abc123",
        "values": {},
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
    assert!(authorize_url.starts_with(
        "https://idp.apis.syseleven.de/realms/application/protocol/openid-connect/auth?"
    ));
    assert!(authorize_url.contains(&format!("code_challenge={code_challenge}")));
    assert!(authorize_url.contains(&format!("nonce={nonce}")));
    assert_eq!(build["redirect_host"].as_str(), Some("127.0.0.1:8080"));

    let idp_mock = idp_server.mock(|when, then| {
        when.method(POST)
            .path("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body_contains("grant_type=authorization_code")
            .body_contains(&format!("code_verifier={code_verifier}"));
        then.status(200)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"id_token": id_token}).to_string());
    });
    let identity_mock = identity_server.mock(|when, then| {
        when.method(POST).path("/auth/tokens");
        then.status(201)
            .header("X-Subject-Token", "keystone-token-value")
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

    idp_mock.assert();
    identity_mock.assert();
    assert_eq!(callback["ok"]["token"].as_str(), Some("keystone-token-value"));
    Ok(())
}
```

- [ ] **Step 2: Build the wasm artifact the test loads**

Run: `cargo build --target wasm32-unknown-unknown --release`
Expected: succeeds (already verified in Tasks 4/6, re-stated here since this test depends on it)

- [ ] **Step 3: Run the test**

Run: `cargo test --test sso_round_trip`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add tests/sso_round_trip.rs
git commit -m "test: add sso build/callback happy-path round trip"
```

---

### Task 8: Nonce-mismatch and project-scope integration tests

**Files:**
- Modify: `tests/sso_round_trip.rs`

**Interfaces:**
- Consumes: `raw_plugin`, `pkce_challenge_for`, `make_id_token` (Task 7).

- [ ] **Step 1: Write the failing tests**

Add to `tests/sso_round_trip.rs`:

```rust
#[test]
fn sso_round_trip_reports_nonce_mismatch_as_guest_error() -> Result<(), Box<dyn std::error::Error>> {
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();

    let code_verifier = "test-code-verifier-0123456789";
    let code_challenge = pkce_challenge_for(code_verifier);
    let id_token_with_wrong_nonce = make_id_token("a-completely-different-nonce");

    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    let build_request = serde_json::json!({
        "identity_url": identity_server.base_url(),
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
        when.method(POST).path("/token");
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
fn sso_round_trip_includes_project_scope_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let idp_server = MockServer::start();
    let identity_server = MockServer::start();

    let code_verifier = "test-code-verifier-0123456789";
    let code_challenge = pkce_challenge_for(code_verifier);
    let nonce = "test-nonce-value";
    let id_token = make_id_token(nonce);

    let mut plugin = raw_plugin(&idp_server.base_url(), &identity_server.base_url())?;

    let build_request = serde_json::json!({
        "identity_url": identity_server.base_url(),
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
        when.method(POST).path("/token");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"id_token": id_token}).to_string());
    });
    let identity_mock = identity_server.mock(|when, then| {
        when.method(POST)
            .path("/auth/tokens")
            .json_body_partial(r#"{"auth": {"scope": {"project": {"id": "proj-123"}}}}"#);
        then.status(201)
            .header("X-Subject-Token", "scoped-token-value")
            .header("Content-Type", "application/json")
            .body("{}");
    });

    let callback_request = serde_json::json!({
        "params": {"code": "raw-code-from-callback"},
        "code_verifier": code_verifier,
        "scope": {"project": {"id": "proj-123"}},
    })
    .to_string();
    let callback_output: String = plugin.call("sso_parse_callback", callback_request.as_str())?;
    let callback: serde_json::Value = serde_json::from_str(&callback_output)?;

    identity_mock.assert();
    assert_eq!(callback["ok"]["token"].as_str(), Some("scoped-token-value"));
    Ok(())
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test sso_round_trip sso_round_trip_reports_nonce_mismatch_as_guest_error sso_round_trip_includes_project_scope_when_configured`
Expected: FAIL — before Task 6, `sso_parse_callback` doesn't exist at all; after Task 6, the test written here should already pass since Task 6's implementation was written against this exact spec shape. If either fails at this point (rather than earlier build failures), treat it as a real bug: re-check `sso_parse_callback`'s `scope`/`project`/`id` field-path reading in Task 6's implementation against this test's `scope` field placement.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test --test sso_round_trip`
Expected: all four tests in `sso_round_trip.rs` PASS

- [ ] **Step 4: Commit**

```bash
git add tests/sso_round_trip.rs
git commit -m "test: cover nonce mismatch and project-scoped auth in sso round trip"
```

---

## Self-Review Notes

**Spec coverage:** `oidc_endpoint`/`client_id`/`redirect_port` config (Task 2), authorize URL shape incl. PKCE+nonce (Task 3/4), `var_set` stash of `oidc_endpoint`/`client_id`/`callback_url`/`nonce` (Task 4), token exchange + nonce validation (Task 5/6), Keystone `/auth/tokens` POST with `methods: ["s11auth"]` and optional `scope.project.id` (Task 5/6/8), `{"ok"|"error"}` return shape everywhere (Task 5), no `state` param / no `project_id` regex / no disk cache (never added, per Global Constraints). Dropped Python-original items are simply absent, not stubbed.

**Placeholder scan:** none — every step has complete code.

**Type consistency:** `resolve_oidc_config` returns `(String, String)` consistently used in Task 4; `extract_keystone_token` takes `&BTreeMap<String, String>` consistently between Task 5's definition and Task 6's call site; helper names match between definition (Task 3/5) and call sites (Task 4/6).

**Note on `redirect_port`:** the spec lists `redirect_port` as a config field but its only consumer is the *host* side (binding the local callback listener before the plugin is ever invoked) — the guest ABI's `sso_build_request` never reads it directly, it only ever sees the resulting `callback_url` already carrying that port. No task here reads `values.redirect_port`; that's correct per the ABI, not a gap.
