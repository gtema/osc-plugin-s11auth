# s11auth wasm plugin

Out-of-tree `sso`-flavor wasm auth plugin implementing `s11auth` (OIDC-via-Keycloak
browser auth against Keystone), conforming to `gtema/openstack`'s plugin ABI v1.
Drop-in replacement for the Python `s11auth` keystoneauth1 plugin.

## Configuration

Set these in the cloud config `auth` block (`values`) the host passes through
to the plugin:

| Field           | Default                                                                    | Purpose                                                                   |
|-----------------|----------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `oidc_endpoint` | `https://idp.apis.syseleven.de/realms/application/protocol/openid-connect` | OIDC issuer base endpoint (Keycloak realm's `openid-connect` root).       |
| `client_id`     | `s11-user`                                                                 | OIDC client id registered with the IdP.                                   |
| `callback_port` | none (ephemeral port)                                                      | Fixed local callback port; must match the IdP's `redirect_uri` allowlist. |

Note: `callback_port` intentionally diverges from the design spec's
`redirect_port` field name — this is a spec bug; the plugin matches the
host's actual `values.get("callback_port")` lookup.

Note: on success, this plugin returns a real `auth_info` (the parsed Keystone
`/auth/tokens` response body) rather than the spec's literal `null` — the
host caches the session from `auth_info`, so a literal `null` would make it
drop the token immediately and force a full browser SSO round trip on every
`osc` invocation.

Note: the Keystone auth request body passes through the full `scope` value
received in the build request verbatim, rather than only `scope.project.id`
as the spec's example shows — this preserves scopes like project-by-name
with a domain, domain scope, and system scope, which the narrower spec
example would silently drop.

## Token validation

The plugin only checks the `id_token`'s `nonce` claim. It does not verify the
signature, `iss`, `aud` or `exp`; the `id_token` is handed to Keystone, which
is responsible for validating it.

## Build

    cargo build --target wasm32-unknown-unknown --release

## Test

Unit tests run natively:

    cargo test --lib

Integration tests load the compiled `.wasm` into a real `extism::Plugin`, so build
it first (CI must run the build step before the tests):

    cargo build --target wasm32-unknown-unknown --release
    cargo test --test sso_round_trip

## Contributing

Install [pre-commit](https://pre-commit.com) and enable the hooks once per
clone:

    pre-commit install

On every commit it checks `cargo fmt` and lints the commit message with
[committed](https://github.com/crate-ci/committed). CI repeats both checks, and
`committed` also runs over every commit of a pull request.

### Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org):

    <type>(<optional scope>): <summary>

    <optional body explaining why, wrapped at 72 characters>

- `type` is one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `chore`, `revert`.
- The summary is imperative ("add", not "added"), has no trailing period and
  stays within 50 characters where possible (72 at most).
- Mark breaking changes with `!` after the type/scope (`feat(auth)!: ...`) and
  describe them in a `BREAKING CHANGE:` footer.
- Merge commits are not allowed: rebase the branch on `main` instead. PRs are
  squash-merged, so the PR title must follow the same format.

`release-plz` derives the next version and the changelog from these messages:
`fix` gives a patch release, `feat` a minor one, a breaking change a major one.
