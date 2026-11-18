# Production guide

What a production deployment of Privacy Guard needs beyond the local stack. Every variable named here is described in
[`.env.example`](../.env.example); the EasyPanel walkthrough is in [`deploy/easypanel`](../deploy/easypanel/README.md).

## 1. Topology

- **app** (root `Dockerfile`): dashboard, API, MCP. The only service with a public domain, behind a TLS-terminating
  proxy (EasyPanel/Traefik, nginx, a cloud load balancer). Session cookies are `Secure` by default; keep
  `SESSION_COOKIE_SECURE=true`.
- **guard-runtime** (`guard-runtime/Dockerfile`): internal only. Never publish its port. For defence in depth turn on
  TLS with client certificates between the two (`GUARD_RUNTIME_TLS_*` on both services); the caller tokens stay
  required either way.
- **PostgreSQL** for the app.
- **Your security API**, reachable from guard-runtime over HTTPS (see [the contract](security-api.md)).

Deploy guard-runtime before the app, since the app checks it at startup and on every status call.

## 2. Database

Use PostgreSQL with the `postgres` profile:

```env
SPRING_PROFILES_ACTIVE=postgres
DATABASE_URL=jdbc:postgresql://<host>:5432/privacyguard
DATABASE_USERNAME=privacyguard
DATABASE_PASSWORD=<secret>
```

The schema comes only from the Flyway migrations in `backend/src/main/resources/db/migration/postgresql`, applied at
startup; Hibernate then validates it against the code and the app refuses to start if they differ. Back up with your
usual PostgreSQL tooling (`pg_dump` or managed snapshots). The H2 default is for evaluation only.

## 3. guard-runtime data

The `/data` volume holds three things; back it up as one unit:

| Path | Content | If lost |
|---|---|---|
| `/data/policy` | Policy versions and their hash-chained history | Policy falls back to the seed file; history is gone |
| `/data/replay` | Consumed one-time capability nonces | A capability issued in the last minutes could be replayed |
| `/data/activity` | Hash-chained activity log | Audit reconciliation in the dashboard shows events as local-only |

guard-runtime stops at startup if the activity log or policy history chain was edited. Restore a consistent backup
instead of editing files.

## 4. Secrets

Generate every secret once (commands in the EasyPanel guide) and keep them in a secret manager. All tokens are
32-512 characters and must differ from each other; the app refuses to start on reuse or on the `replace-with-`
placeholders from `.env.example`.

| Secret | Lives in | Rotation |
|---|---|---|
| `GUARD_RUNTIME_*_TOKEN` | app and guard-runtime (`GUARD_RUNTIME_CALLERS_JSON`) | Change both, restart guard-runtime then the app |
| `SECURITY_API_KEY` | guard-runtime (and your security API) | Change both sides together |
| `REMEDIATION_AUTH_PRIVATE_KEY_PKCS8` / `REMEDIATION_AUTH_PUBLIC_KEY_SPKI` | app / guard-runtime | New key id; keep the old public key in `REMEDIATION_AUTH_PREVIOUS_*` for the grace period |
| `AUDIT_INTEGRITY_KEY` | app | New key id; keep `oldId=oldKey` in `AUDIT_INTEGRITY_PREVIOUS_KEYS` while old events are retained |
| `MCP_TOKEN`, `METRICS_TOKEN`, `GUARD_RUNTIME_METRICS_TOKEN` | app / guard-runtime | Change and restart; update the agent or scraper |
| `OIDC_CLIENT_SECRET` | app | Rotate in the identity provider, then here |

## 5. Sign-in

Use single sign-on and turn local accounts off:

```env
OIDC_ISSUER_URI=https://login.example.com/...
OIDC_CLIENT_ID=<client id>
OIDC_CLIENT_SECRET=<secret>
OIDC_ROLE_MAPPING={"ANALYST":["..."],"APPROVER":["..."],"EXECUTOR":["..."],"AUDITOR":["..."],"POLICY_ADMIN":["..."]}
LOCAL_LOGIN_ENABLED=false
```

Register the redirect URI `https://<app-domain>/login/oauth2/code/sso` in the provider and enforce MFA there.

| Provider | Issuer | Roles claim |
|---|---|---|
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | `groups` (group object ids; enable the groups claim in the app registration) |
| Okta | `https://<org>.okta.com/oauth2/default` | `groups` (add a groups claim to the authorization server) |
| Keycloak | `https://<host>/realms/<realm>` | `realm_access.roles` or a groups mapper |
| Google Workspace | `https://accounts.google.com` | no groups in the token; map through a custom claim or use another provider |

For separation of duties map APPROVER and EXECUTOR to different groups. The app also refuses to let the person who
approved a remediation execute or verify it, whatever groups they hold.

## 6. Monitoring

Both services serve Prometheus metrics at `/actuator/prometheus` to a scraper presenting the bearer token
(`METRICS_TOKEN` for the app, `GUARD_RUNTIME_METRICS_TOKEN` for guard-runtime). `/actuator/health` is open for uptime
checks.

```yaml
scrape_configs:
  - job_name: privacy-guard-app
    scheme: https
    metrics_path: /actuator/prometheus
    authorization: { credentials: <METRICS_TOKEN> }
    static_configs: [{ targets: ['<app-domain>'] }]
  - job_name: privacy-guard-runtime
    metrics_path: /actuator/prometheus
    authorization: { credentials: <GUARD_RUNTIME_METRICS_TOKEN> }
    static_configs: [{ targets: ['guard-runtime:3101'] }]
```

Suggested alerts:

| Alert | Expression |
|---|---|
| Service down | `up{job=~"privacy-guard.*"} == 0` |
| Remediation not verified | `increase(privacy_guard_remediations_total{outcome=~"UNVERIFIED\|FAILED"}[15m]) > 0` |
| guard-runtime refusing calls | `increase(guard_runtime_calls_total{outcome=~"error\|denied"}[15m]) > 10` |
| Unusual blocking | `increase(privacy_guard_decisions_total{decision="DENY"}[1h]) > 20` (tune to your baseline) |
| Sign-in attacks | `increase(privacy_guard_login_failures_total[15m]) > 20` |

Every `UNVERIFIED` remediation needs a person: it is never retried automatically.

## 7. Retention

`INCIDENT_RETENTION_DAYS` (1-3650, default 7) applies to incidents and their audit trail, which are deleted together.
Choose the shortest period your obligations allow; export what you must keep longer before it expires.

## 8. Upgrades

Each release is the pair of images built from one commit. Deploy guard-runtime, then the app; database migrations run
when the app starts. To roll back, redeploy the previous pair. A database migration is never undone automatically, so
restore the backup taken before the upgrade if a release with a migration has to be rolled back.

### CVE-2026-114938 (Java4Shell): JVM mitigation and deployment verification

Both Java services use Eclipse Temurin 21 (`eclipse-temurin:21.0.12_8-jre` in the runtime stages as of
2026-11-18). An unpatched HotSpot JVM can select a vulnerable Base64 decoder on x86-64 machines exposing AVX-512
VBMI when untrusted Base64 reaches the decoder. A Dockerfile tag, application POM, or merge does **not** establish
the CPU, effective Java flags, or image deployed on a host.

The root `Dockerfile` and `guard-runtime/Dockerfile` explicitly pass `-XX:-UseBASE64Intrinsics` to their Java
`ENTRYPOINT`. This is the narrow, **temporary** workaround recommended by
[Red Hat RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018). It disables the
accelerated Base64 intrinsic on supported HotSpot JREs, including on hosts where that CPU feature is absent; it may
reduce Base64 throughput. Existing `JAVA_TOOL_OPTIONS` are left intact, and the explicit launcher argument keeps the
mitigation in the default command.

After a merge, **rebuild and recreate both containers** (guard-runtime before app); running containers keep their
old JVM and command line until replaced. With access to the actual Docker host, record the following for **each**
running container (replace `<container>` and `<image>` with the deployed names):

```sh
uname -m
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$' || true
docker inspect --format 'image={{.Config.Image}} image_id={{.Image}} entrypoint={{json .Config.Entrypoint}}' <container>
docker image inspect --format '{{json .RepoDigests}}' <image>
docker exec <container> java -version
docker exec <container> sh -c 'tr "\000" " " </proc/1/cmdline; echo'
docker exec <container> java -XX:-UseBASE64Intrinsics -XX:+PrintFlagsFinal -version 2>&1 | grep UseBASE64Intrinsics
```

The last command checks acceptance of the flag **in a separate JVM**, not the effective flags of the running
process. Inspect its actual Java command line (or run `jcmd <pid> VM.flags -all` if a compatible JDK attachment
tool is available) to verify that `UseBASE64Intrinsics` is disabled in that process. An orchestration override of
`ENTRYPOINT`, an old container, or an unavailable image digest requires further investigation. Locally built
images may have no `RepoDigests`; preserve their immutable image ID and source commit as evidence instead.
A missing `avx512vbmi` CPU flag reduces known exposure on that host but does not remove the need to keep the
defensive configuration through future host changes.

When Eclipse Temurin provides a **published, vendor-confirmed fixed container image** for the required Java 21
architecture, verify its release, tag, image digest and actual `java -version`, then update both runtime stages and
rebuild/redeploy both images. Do not treat a floating tag or the unpatched `21.0.13+9` line as proof of a fix; on
2026-11-18 the Adoptium [support table](https://adoptium.net/support/) listed `21.0.13.1` as a future release.
Only remove the temporary JVM flag in a subsequent reviewed change after a fixed JRE is confirmed and both
deployed runtimes have been verified. Verify service health and benchmark Base64-heavy workloads after rollout.

## 9. Before real data

- Run an independent penetration test against your deployment.
- Decide what may be sent to the AI provider: prompts leave your network unless `AI_API_URL` points to a model you host.
  The prompt guard blocks obvious secrets and personal data but is not a complete classifier.
- Read the limits in the [README](../README.md#limits).
