# Postern Registry HTTP API

This is the contract for a Postern-compatible device-inventory HTTP service. Postern's broker calls your service every time an engineer requests an SSH certificate, to translate whatever the engineer typed (a friendly device name, a serial, a customer ID — operator's call) into the canonical hardware serial that goes into the SSH certificate.

You're implementing the **server**. Postern is the **client** (it ships the client code; you don't need to look at it).

## At a glance

- One endpoint: `GET <your-url>?device_id=<value>`
- JSON in/out
- `200` with the resolved record on success
- `404` when the device id isn't known
- Anything else is treated as "your service is having a problem"
- ~Sub-second response expected on the hot path (each `postern ssh` invocation calls you once)

## The endpoint

**Method:** `GET`

**URL:** whatever URL you publish. Operators configure the broker with the exact URL via `registry.http_url`. The path is up to you (e.g. `https://inventory.example.com/postern/lookup`, `https://api.example.com/v1/devices`).

**Query parameter:** `device_id` — URL-encoded. This is whatever the engineer typed on the command line. It might be:
- A canonical hardware serial (`1424223030014`)
- A friendly identifier (`prod-a012`, `lab-rover-7`)
- A customer-issued ID (`ACME-12345`)
- Anything else your inventory recognizes

Your service decides what's resolvable. Postern doesn't care about the format; it just passes the string through.

**Headers Postern sends:**
- `Accept: application/json`
- `User-Agent: postern-broker`
- `Authorization: <...>` — only when the broker is configured for auth; see "Authentication" below.

## Successful response: `200 OK`

Return JSON:

```json
{
  "serial": "1424223030014",
  "friendly_id": "prod-a012",
  "attributes": {
    "fleet": "production",
    "owner_team": "robotics",
    "site": "warehouse-3",
    "in_production": true,
    "firmware_revision": 42
  }
}
```

**Fields:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `serial` | string | **yes** | The canonical hardware serial. This becomes the SSH cert's principal — `device-{serial}-operator`. The on-device sshd authorizes based on this exact string, so it must match what the device reports as its own serial. |
| `friendly_id` | string | no | A human-readable identifier for audit logs and policy decisions. Show whatever your engineers think of as "the name" of this device. |
| `attributes` | object | no | Arbitrary key/value metadata that flows into the broker's authorization policy. Keys are always strings. **Values may be string, boolean, or integer** — these map to Cedar's `String`, `Boolean`, and `Long` types respectively. JSON numbers with a fractional part (e.g. `1.5`), `null`, arrays, and nested objects are silently dropped. Empty / whitespace-only strings are silently dropped (but `false` booleans and `0` integers are kept — those are meaningful values). |

**Cedar schema reminder.** The broker's AVP policy store runs in STRICT validation mode: policies that reference an attribute the schema doesn't declare fail to compile. If you start emitting a bool or integer attribute the policy needs to read, extend the policy store's Cedar schema (`Device` entity shape) to declare it — the broker's terraform module exposes an `avp_schema_json` variable for that purpose.

Notes:
- `serial` is the only field the broker strictly needs. Everything else is optional.
- Return the same `serial` regardless of which identifier the engineer typed. If `prod-a012` and `1424223030014` both refer to the same physical device, your service must resolve both lookups to the same `serial`.
- Whitespace in `serial`, `friendly_id`, and attribute keys/values is trimmed by the client; you can return it either way.

## Device not found: `404 Not Found`

Return `404` with any (or no) body. The broker translates this into "device id is unknown" and the engineer sees a clean error.

Don't return `200` with a missing or empty `serial`; that's treated as a server malfunction (see below).

## Anything else (500, 502, 503, timeout, malformed JSON, missing serial)

The broker treats any non-`200` non-`404` response — and any response that can't be JSON-decoded or has an empty `serial` — as a Registry dependency failure. The engineer sees an "upstream not available" style error and the cert request fails.

So:
- `404` = "this device id is not in my inventory" (engineer's mistake)
- `200` with a valid `serial` = "found it, here's the canonical record"
- Everything else = "my service is broken right now" (operator's mistake)

If you want to communicate a specific failure reason (rate-limited, maintenance mode, etc.), include it in the body — the broker logs the response body for the operator to diagnose, even though the engineer-facing error stays generic.

## Authentication

The broker supports three authentication modes for outgoing registry calls. The operator picks one via `registry.http_auth_mode` in the broker config (or the corresponding `POSTERN_REGISTRY_HTTP_AUTH_MODE` env var).

### Mode: `none` (default)

The broker sends no `Authorization` header. Use one of:

- **Trusted network path.** The registry endpoint is only reachable from the broker's network (private VPC, internal DNS, etc.).
- **mTLS at the load balancer.** Your service requires a client cert; the broker's deployment puts that cert on the broker.
- **IP allowlist.** Broker has a stable egress IP; your service rejects everything else.

### Mode: `bearer`

The broker sends `Authorization: Bearer <token>` on every request. The token is configured at the broker side via:

- `registry.http_bearer_token` in the broker's YAML config, **or**
- `POSTERN_REGISTRY_HTTP_BEARER_TOKEN` environment variable (recommended — keeps the secret out of YAML).

On your side, implement standard bearer-token validation. Compare the presented token against what the operator configured for your service. Reject (`401 Unauthorized`) if missing or wrong; the broker treats any non-`200`/non-`404` as a service-side failure, so the engineer sees a generic error and the operator can diagnose from your logs.

### Mode: `aws_sigv4`

The broker signs every request with AWS SigV4 against the `execute-api` service. Use this when your registry is fronted by **AWS API Gateway** with IAM authorization enabled. API Gateway itself validates the SigV4 signature against the broker's IAM identity; your backing Lambda or integration sees a clean, already-authenticated request and only needs to enforce the IAM permission (typically `execute-api:Invoke` on the specific API Gateway resource ARN).

What the broker sends on each request:

- `Authorization: AWS4-HMAC-SHA256 Credential=<access-key>/<date>/<region>/execute-api/aws4_request, SignedHeaders=..., Signature=...`
- `X-Amz-Date: 20260512T180000Z` (canonical timestamp)
- `X-Amz-Security-Token: <session-token>` (only when the broker's credentials are temporary — typical for IAM roles)

The broker's credentials come from the AWS SDK's default chain — environment variables, shared config files, IMDS, ECS task role, or Lambda execution role — so a broker running as a Lambda function or ECS task automatically signs with that task's IAM identity. No long-lived AWS keys need to live in broker config.

The region is taken from `registry.http_aws_region` (or `POSTERN_REGISTRY_HTTP_AWS_REGION`); when empty, the SDK's default-region resolution applies (`AWS_REGION` env, shared config, etc.).

**For implementers:** if you're using API Gateway, you don't implement SigV4 verification yourself. Set the API Gateway authorization type to `AWS_IAM` (or `NONE` if you want to delegate auth to a resource policy / Lambda authorizer) and grant the broker's IAM role `execute-api:Invoke` on the relevant resource ARN. The signed request lands at your Lambda/integration with auth already verified.

### Other auth schemes

If your service needs something else — custom JWT, HMAC of the query, mTLS plus a header, etc. — the v1 HTTP Registry doesn't speak it directly. Options:

- Put a proxy in front of your service that translates the broker's auth (or lack of it) into what your service expects.
- Wrap the Postern broker with your own Registry implementation that adds the header (this requires forking the broker binary or using Postern as a library).

## Performance expectations

- **Latency:** The broker has a default 15-second timeout per request (configurable via `registry.http_timeout` / `POSTERN_REGISTRY_HTTP_TIMEOUT` / the Terraform module's `registry_http_timeout` variable). The default is sized for a Lambda-fronted-by-API-Gateway registry's cold-start budget; aim for **p99 under 500ms** in steady state so the cert-issue path doesn't feel slow. Operators with on-network sub-second p99 registries typically tighten the timeout. The broker calls you on every engineer's `postern ssh` invocation, but with cert caching that's typically once per device per ~12 hours per engineer.
- **Throughput:** Modest. A small operator might have ~10 engineers issuing ~5–20 cert requests each over a workday. Bursts during incidents or scripted operations are possible (one engineer requesting certs for 500 devices in a loop is a legitimate workflow).
- **Idempotency:** GET-only, no side effects expected. Repeated calls with the same `device_id` should return the same record (unless inventory genuinely changed).
- **Caching:** The broker does not cache your responses across requests. If your inventory lookup is expensive (database hop, third-party API call), cache on your side. A short server-side TTL (30s–5min) is reasonable.

## Implementation checklist

For a colleague writing a new service from scratch:

- [ ] Pick a URL path. Document it.
- [ ] Accept `GET` with `?device_id=<value>`. URL-decode it.
- [ ] Look the value up in your inventory.
- [ ] If found: return `200` with `{serial, friendly_id?, attributes?}` as JSON.
- [ ] If not found: return `404`.
- [ ] On any internal error: return `5xx`. Don't return `200` with an empty body.
- [ ] Log incoming requests with the `device_id` and outcome — useful for operators correlating with broker logs when something is misconfigured.
- [ ] Add a `/healthz` (or whatever your shop uses) so the operator can monitor it. Postern doesn't probe health itself.
- [ ] Decide auth: trusted network / bearer token / AWS IAM (via API Gateway) / mTLS / IP allowlist / front-proxy.
- [ ] Test with `curl`:
  ```sh
  curl -i 'https://<your-url>?device_id=prod-a012'
  curl -i 'https://<your-url>?device_id=does-not-exist'
  ```

## End-to-end smoke test

Once your service is up and the operator has configured `registry.http_url`, an engineer running:

```sh
postern login
postern mint prod-a012
```

should reach your service exactly once, get a `200` with the resolved serial, and Postern then mints a cert whose principal is `device-<your-returned-serial>-operator`. If `prod-a012` isn't in your inventory, the engineer sees a 404-style error pointing at the device id, not at your service.

## Reference

Postern's broker is open source. The client that calls your service lives at `internal/registry/http.go` in the Postern repo if you want to confirm exact byte-level behavior. The authoritative architecture is `DESIGN.md`'s "Registry" sections.
