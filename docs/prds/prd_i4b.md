# I4b: Verify initial Claude Code sign-in

Parent: [I4](prd_i4.md) · related: [provider setup contract](prd_i4d.md)

Owner: **Codex**, within **Outside-in integrations**. Scope is the first-party workstation
login and a later readiness check without inference. Existing devbox evidence shows Claude
Code 2.1.330 reports a cached Claude.ai login with a future expected expiry. A fresh sign-in
and reuse from the intended workstation placement remain open.

- [ ] Resolve the operator-installed `claude` binary from trusted workstation settings or
  trusted PATH. Qualify the supported version and prove the probe runs with a clean environment,
  outside the checkout, with no inherited API key, gateway override or workspace customization.
- [ ] Use a clean, disposable native profile for the attended first sign-in where the native
  CLI supports it. Guide the operator to `claude auth login` in their own workstation terminal.
  Leave interaction with the browser and native prompts to the operator. Preserve their existing
  login and do not collect or copy native credentials.
- [ ] Start a fresh process and check native `claude auth status` for the expected first-party
  Claude.ai method, rejecting alternate billing or identity routes. Project only readiness and
  any supported expiry indicator. Test missing binary, signed-out profile, cancel, unusable
  status and absent or expired expiry. Verify there are zero model prompts.
- [ ] Record native sign-in evidence and keep subscription routing subject to
  [I4 Stage 0](prd_i4.md#feasibility-spike--host-only-claude-subscription-routing).
  Keep fresh sign-in and credential isolation qualification separate from worker acceptance.

[Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference) ·
[Claude Code authentication and compliance](https://code.claude.com/docs/en/legal-and-compliance)
