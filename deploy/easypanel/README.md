# EasyPanel

Privacy Guard runs as two **App** services in one EasyPanel project, both built from this GitHub repository on every
push to `main`. guard-runtime stays internal; only the app gets a public domain.

Deploy guard-runtime first, then the app. Secrets are generated once (see [Secrets](#secrets)) and pasted into the
services' Environment tab; the same value goes to both services where marked.

## Service `guard-runtime`

| Setting | Value |
|---|---|
| Source | GitHub, this repository, branch `main` |
| Build | Dockerfile, build path `/guard-runtime`, file `Dockerfile` |
| Domain | none (internal only) |
| Mounts | volume `guard-runtime-data` at `/data` (policy versions, replay store, activity log) |

Environment:

```env
GUARD_RUNTIME_TENANT_ID=your-organization
GUARD_RUNTIME_CALLERS_JSON=[{"id":"agent:proposal","token":"<PROPOSAL_TOKEN>","functions":["evaluate-action"]},{"id":"agent:executor","token":"<EXECUTOR_TOKEN>","functions":["execute-remediation","verify-remediation"]},{"id":"agent:policy-admin","token":"<POLICY_ADMIN_TOKEN>","functions":["manage-policy"]}]
GUARD_RUNTIME_VERIFIED_EMAIL=security-contact@your-company.com
SECURITY_API_URL=https://<app-domain>/api/security/remediation/execute
SECURITY_VERIFICATION_URL=https://<app-domain>/api/security/remediation/verify
SECURITY_API_KEY=<SECURITY_API_KEY, same as the app>
REMEDIATION_AUTH_KEY_ID=primary
REMEDIATION_AUTH_PUBLIC_KEY_SPKI=<CAPABILITY_PUBLIC_KEY>
```

`SECURITY_API_*` above point at the app's built-in security adapter. With your own security tooling, use its HTTPS
URLs and credential instead (see [the security API contract](../../docs/security-api.md)).

The image starts from a seed policy (`guard-runtime/policy/privacy-guard-policy.json`). Its remediation actions allow
`api-privacy.iforce.com.br`; if your app domain is different, open the dashboard's **Policy** tab after the first
deploy, add your domain to the hosts of `revoke-credential` and `notify-security` and publish. Until then the status
bar reports the integration as not ready.

## Service `app`

| Setting | Value |
|---|---|
| Source | GitHub, this repository, branch `main` |
| Build | Dockerfile, build path `/`, file `Dockerfile` |
| Domain | `https://<app-domain>` → port `8080` (EasyPanel terminates TLS) |
| Mounts | volume `app-data` at `/data` (only needed with the default H2 database) |

Environment:

```env
GUARD_RUNTIME_URL=http://<project>_guard-runtime:3101
GUARD_RUNTIME_PROPOSAL_TOKEN=<PROPOSAL_TOKEN>
GUARD_RUNTIME_EXECUTOR_TOKEN=<EXECUTOR_TOKEN>
GUARD_RUNTIME_POLICY_ADMIN_TOKEN=<POLICY_ADMIN_TOKEN>
SECURITY_API_KEY=<SECURITY_API_KEY, same as guard-runtime>
REMEDIATION_AUTH_KEY_ID=primary
REMEDIATION_AUTH_PRIVATE_KEY_PKCS8=<CAPABILITY_PRIVATE_KEY>
AUDIT_INTEGRITY_KEY=<AUDIT_INTEGRITY_KEY>
OPERATOR_USERNAME=operator
OPERATOR_PASSWORD=<OPERATOR_PASSWORD>
# Optional
MCP_TOKEN=<MCP_TOKEN>
AI_PROVIDER=openai-compatible
AI_API_URL=https://api.openai.com/v1/chat/completions
AI_API_KEY=<provider key>
AI_MODEL=<model>
```

`GUARD_RUNTIME_URL` uses the internal hostname EasyPanel shows for the guard-runtime service (usually
`<project>_guard-runtime`). Names with an underscore work over `http://` with the port, which is how services talk
inside the project network.

Every other setting (separation-of-duties accounts, SSO, PostgreSQL, retention, incident intake) is described in
[`.env.example`](../../.env.example) and the [production guide](../../docs/production.md).

## Secrets

Run once on any machine with OpenSSL and keep the output in your password manager:

```bash
for name in PROPOSAL_TOKEN EXECUTOR_TOKEN POLICY_ADMIN_TOKEN SECURITY_API_KEY AUDIT_INTEGRITY_KEY OPERATOR_PASSWORD MCP_TOKEN; do echo "$name=$(openssl rand -hex 32)"; done
openssl genpkey -algorithm ed25519 -out capability.pem
echo "CAPABILITY_PRIVATE_KEY=$(openssl pkey -in capability.pem -outform DER | openssl base64 -A)"
echo "CAPABILITY_PUBLIC_KEY=$(openssl pkey -in capability.pem -pubout -outform DER | openssl base64 -A)"
rm capability.pem
```

## Moving from the Terminal 3 deployment

The former deployment had three services (`frontend`, `backend`, `t3n-gateway`). Their Dockerfiles no longer exist,
so their builds fail and EasyPanel keeps the last running containers until you switch:

1. Create `guard-runtime` as above, or repoint `t3n-gateway` to build path `/guard-runtime` and replace its
   environment. Reuse the old `REMEDIATION_AUTH_PUBLIC_KEY_SPKI`, `REMEDIATION_AUTH_KEY_ID` and `SECURITY_*` values.
2. Turn `backend` into the app: change its build path from `/backend` to `/` and its port to `8080`. Keep its
   volume and its `AUDIT_INTEGRITY_KEY`, `OPERATOR_*`, `SECURITY_API_KEY` and `REMEDIATION_AUTH_PRIVATE_KEY_PKCS8`, so
   existing incidents and their audit chains stay readable. Remove the `T3N_*` and gateway variables and add the
   `GUARD_RUNTIME_*`, `MCP_TOKEN` and `AI_*` ones listed above (the AI settings used to live on the gateway).
3. Move the dashboard's domain from `frontend` to the app (it now serves the dashboard and the API on one domain),
   then delete `frontend` and, if you created a new guard-runtime service, `t3n-gateway`.
