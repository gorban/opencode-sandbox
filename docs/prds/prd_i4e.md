# I4e: Amazon Bedrock provider

Parent: [I4 model gateway](prd_i4.md) · related: [provider configuration](prd_i4d.md),
[worker credential isolation](prd_i3a.md)

Backlog after the initial workstation subscription routes. Bedrock is a separate metered AWS
route with explicit account, model and regional policy. Use api-agent's Bedrock implementation
at `7b6ded36077d` as a design reference (`docs/bedrock.md` and
`src/api_agent/llm_providers/bedrock/`). Independently qualify the routes adopted by oc-sandbox.

## Authentication and rollout

| Mode | Workstation credential source | First qualification |
| --- | --- | --- |
| `session` | An explicit SDK profile or qualified role that actually yields temporary credentials. It may use AWS IAM Identity Center or another supported session provider. | Prefer first. Verify the expected AWS account, role or principal, region and expiry. Allow a new role-session name on refresh under the same verified role. An attended native AWS login may be offered for eligible named profiles. |
| `access_key` | One versioned host-vault entry for the access key ID and secret access key for SigV4. Reject session-token-bearing credentials in this mode. | Keep it opt-in and test exact identity, denied rotations and revocation. |
| `api_key` | Host-vault reference to a Bedrock bearer token. Prefer short-lived tokens. | Check the exact endpoint, API operation and model. Token issuance or renewal is a separate workstation capability. A bearer invocation does not establish the paying account. Require supported account evidence where policy requires that binding. |

Start with one named `session` instance, a pinned region and model, and Bedrock Runtime Converse.
Qualify `access_key` and `api_key` afterwards. Keep Mantle, Responses and Chat Completions as
separate compatibility checks. Model catalog discovery does not prove permission to invoke a
specific model. Bind each lease to the stable instance, exact mode, credential-binding generation,
verified account and principal wherever required by policy, endpoint, source region, inference
profile, model and cost policy. Replacing the configured credential source advances the binding
generation. Routine temporary credential refresh preserves the binding only after re-verifying
the same account and role or principal. Meter on the host and require the applicable authority
for paid inference. The worker receives its scoped broker capability.

## Acceptance

- [ ] Review the provider schema and session recovery against api-agent's three modes. Pin a
  least-privilege SDK credential source per instance. Exclude unexpected ambient credentials,
  metadata endpoints and credential-process commands from unreviewed configuration. Keep login
  and refresh on the workstation. Never fall through to another account, mode or region.
- [ ] With synthetic credentials and a fake AWS peer, cover endpoint and signing-region admission,
  per-instance identity isolation, denied refresh, expiry, revocation, redaction and bounded
  streaming. Verify scoped worker access and zero visibility of AWS profiles, caches or secrets.
  A new session name under the approved account and role can continue. A different role in the
  same account must invalidate the lease before dispatch.
- [ ] Qualify one exact, cost-bounded model after fake coverage and review. Confirm identity and
  invocation permission separately where the selected authentication method supports them. Repeat
  admission checks for bearer-only identity and hold ambiguous account or billing claims open.
- [ ] Review AWS-supported API, model and inference-profile combinations before expanding the
  route. Require explicit consent for cross-region or global routing and separate authority for
  each first live paid test. In the fake suite, refuse an inference profile that allows destinations
  outside the approved set even when the request targets the approved regional endpoint. Keep the
  remaining combinations unavailable until qualified.

[Bedrock API compatibility](https://docs.aws.amazon.com/bedrock/latest/userguide/models-api-compatibility.html) ·
[Bedrock API keys](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)
