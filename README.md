# Update Server — Flask MVP

Multi-tenant update server for Windows & Linux fleets of PC's . Admin UI (Bootstrap), agent API, artifacts με Range streaming, health/ready, metrics, Swagger, rate-limits, scheduler, pricing.

## Dev quick start
```bash
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python manage.py db-init or flask db upgrade
flask --app wsgi:app run -h 0.0.0.0 -p 8080
```
- Admin UI: http://localhost:8080/
- Swagger:    /apidocs
- Health:     /health
- Ready:      /ready
- Metrics:    /metrics



<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/45325108-f677-4dab-8f01-0bf686998cbc" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/377129dc-9eb8-4352-b492-60e5af393245" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/6ce0d385-b34e-42c8-8a46-17d9fd5882e7" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/78023a3e-568e-47c4-91aa-32987d8e0722" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/f1d52ce2-d20a-4792-8866-8ecec2380477" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/31a822ee-e5d3-4412-8176-25fe44f7a99a" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/a5f90834-ad27-4aab-bb57-43fd9e5a94ef" />



# Update Server & Agent Protocol (v1.2, 2025‑10‑02)

This document defines the **wire protocol**, **server behaviors**, **data model expectations**, and **admin UI flows** for the Update Server and the simulated/real Update Agent.

It reflects the latest code paths you have, including:
- Tenant-scoped API key auth with header `X-API-Key`.
- Artifact lookup at `/api/updates/<package_id>/<semver>` with HTTP range support.
- Heartbeat **auto‑enqueue** with strict rollout target matching:
  - If a rollout specifies Fleets **and** Device IDs → **intersection** (device must be in one of the fleets **and** in the device ID list).
  - If a rollout specifies only Fleets → any device in those fleets.
  - If only Device IDs → only those devices.
  - If no targets → global.
- Retry behavior on `failed` `device_installation` rows.
- Admin pages for Packages / Rollouts and the JSON device picker (`/devices.json`).

> All timestamps are UTC unless otherwise stated. The server runs Flask; persistence is SQLAlchemy → SQLite by default (`instance/updates.db`). Artifacts are stored under `ARTIFACTS_ROOT` (default: `instance/artifacts`).

---

## 1) Authentication & Tenancy

### 1.1 API Key
Agents authenticate every API call with an API key header:

```
X-API-Key: <plaintext-key>
```

Server side, the plaintext is hashed (sha256) and matched to a row in `api_key` with:
- `tenant_id` → which **tenant** the key belongs to
- `scopes` → must include `agents`
- `expires_at` → if present, must be in the future

On successful resolution the request context (`flask.g`) is populated:
- `g.tenant_id` → used to scope **every** query
- `g.api_key_id` → stored for audit/logging

### 1.2 Tenant Guard
Every endpoint is either behind `@require_tenant` or imports `resolve_tenant_from_api_key()` via a blueprint `before_request` hook. **All reads/writes** are tenant-filtered by `g.tenant_id`.

---

## 2) Core Endpoints (Agent API)

Base URL shown as `https://server.example.com` below (use your actual host/port).

### 2.1 Register Agent
`POST /api/agents/register`

Registers (or upserts) a device by hostname + fleet under the current tenant.

**Headers**
```
X-API-Key: <key>
Content-Type: application/json
```

**Request Body**
```json
{
  "hostname": "agent-001",
  "fleetId": 1
}
```

**Response 200**
```json
{
  "deviceId": 24,
  "status": "idle"
}
```

- If a device with the same `(tenant_id, hostname)` exists → returns existing `deviceId`.
- Required: `hostname` (non-empty), `fleetId` (positive int).

### 2.2 Heartbeat
`POST /api/agents/heartbeat`

Announces presence and fetches actions for the device. This is also where the server may **auto‑enqueue** a pending installation for any **due** rollout targeting this device (see §4).

**Headers**
```
X-API-Key: <key>
Content-Type: application/json
```

**Request Body**
```json
{
  "deviceId": 24,
  "agentVersion": "1.2.0",
  "osVersion": "Windows 11"
}
```

**Response 200**
```json
{
  "actions": [
    { "action": "install", "packageId": 1, "version": "1.0.1" }
  ],
  "throttleSeconds": 0
}
```

- The server updates: `last_seen_at`, `last_ip` (uses `X-Forwarded-For` if present), `agent_version`, `os_version`.
- If there is **no applicable pending** `device_installation`, the server scans **due** rollouts and **enqueues** one `pending` row if targeting rules match.
- If a **`pending`** exists (and still matches targets), an **install** action is returned.

**HTTP Errors**
- `404 {"error":"device_not_found"}` if `deviceId` doesn’t belong to the current tenant.
- `200 {"actions":[]}` is valid when nothing to do.

### 2.3 Download Artifact
`GET /api/updates/<package_id>/<semver>`

Downloads the artifact for a specific package version. Supports range requests, resumes and streaming.

**Headers**
```
X-API-Key: <key>
```

**Responses**
- `200 OK` (full body) or `206 Partial Content` (when `Range` header is used).
- Headers: `Accept-Ranges: bytes`, `Content-Disposition: attachment; filename="<basename>"`, `Content-Type: application/zip` (or inferred MIME).
- `404 {"error":"package_version_not_found"}` if the `<package_id>/<semver>` pair cannot be resolved **under the same tenant**.

**Examples**
```bash
# Full download
curl -H "X-API-Key: $API_KEY"   -o ./unx-1.0.1.zip   https://server.example.com/api/updates/1/1.0.1

# Resume (partial)
curl -H "X-API-Key: $API_KEY"      -H "Range: bytes=1024-"      -o ./unx-1.0.1.zip      https://server.example.com/api/updates/1/1.0.1
```

### 2.4 Report Install Results
`POST /api/agents/install-results`

The agent reports the outcome after it attempts an install.

**Headers**
```
X-API-Key: <key>
Content-Type: application/json
```

**Request Body**
```json
{
  "deviceId": 24,
  "packageId": 1,
  "version": "1.0.1",
  "status": "succeeded",
  "message": "ok"
}
```

**Response 200**
```json
{ "ok": true }
```

**Status Normalization**
Incoming `status` is normalized into one of:
- `in_progress` (includes: `pending`, `installing`, `running`)
- `succeeded` (includes: `success`, `ok`, `completed`, `done`)
- `failed` (includes: `fail`, `error`)

On `succeeded`/`failed` the server sets `finished_at` if not already set.

If no `device_installation` row exists for the tuple `(deviceId, packageId, version)`, the server **creates one** and updates its status accordingly. The server also links the row to the most recent `rollout` for this tenant/package/version **if** the device matches that rollout’s targets (see §4.3).

---

## 3) Data Model (Relevant Tables)

### 3.1 Device
- `id` (PK)
- `tenant_id`
- `fleet_id`
- `hostname`
- `status` (`idle` or freeform)
- `agent_version`, `os_version`
- `last_seen_at`, `last_ip`

Unique-ish by `(tenant_id, hostname)` from register flow.

### 3.2 Package
- `id` (PK)
- `tenant_id`
- `name`
- `description`

### 3.3 PackageVersion
- `id` (PK)
- `package_id` (FK → Package.id)
- `semver` (string; e.g., `1.0.1`)
- `hash_sha256`, `size_bytes`, `signed` (bool), `release_notes`
- `storage_path` (absolute path on server FS)
- `created_at` (optional in schema)

Artifact files are placed under:
```
ARTIFACTS_ROOT/<tenant_id>/<package_id>/<semver>.<ext>
```
e.g. `instance/artifacts/1/1.0.1/unx.zip`

### 3.4 Rollout
- `id` (PK)
- `tenant_id`
- `package_id`
- `version` (semver string; must map to a `PackageVersion`)
- `status`: `scheduled` | `running` | `paused` | `cancelled`
- `start_at` (when eligible to begin)
- `waves` (string, e.g., `"[100]"`; reserved for future wave logic)
- `concurrency_limit` (reserved)
- `maintenance_window` (freeform)
- `policy_json` (JSON string; server ensures it contains `"waveIndex"`)

### 3.5 RolloutTarget
- `id` (PK)
- `rollout_id` (FK → Rollout.id)
- Either `fleet_id` or `device_id` (or none → global).

> **Targeting semantics are defined in §4.2.**

### 3.6 DeviceInstallation
- `id` (PK)
- `device_id`
- `package_id`
- `version` (semver string)
- `status`: `pending` | `in_progress` | `succeeded` | `failed` | (`installing`/`running` normalize to `in_progress`)
- `rollout_id` (nullable FK → Rollout.id)
- `started_at`, `finished_at` (nullable)

**Uniqueness**: Not strictly unique; multiple rows for the same `(device, package, version)` may exist over time (e.g., retries). The heartbeat logic will use the **most recent** row and avoid duplicates (see §4.1).

---

## 4) Heartbeat Behavior & Targeting

### 4.1 High-Level Flow
1. Validate `deviceId` is owned by the tenant from the API key.
2. Update device telemetry (IP, last_seen, versions).
3. Find an **applicable** `pending` installation (latest), only if it:
   - Belongs to a **due** rollout (`status in [scheduled, running]` AND `start_at <= now`) **and**
   - The rollout **targets** this device per §4.2.
4. If none found:
   - Iterate **due** rollouts for the tenant.
   - For the **first** rollout that **targets** the device and has a valid `PackageVersion`:
     - If there’s a recent `DeviceInstallation` with `status = failed`, **retry** by enqueuing a **new** `pending`.
     - If there’s a `pending`, reuse it.
     - If there’s `in_progress` or `succeeded`, skip.
5. Return actions. At most one install action per heartbeat.

### 4.2 Target Matching (strict)
Let the rollout have:
- **Fleet targets**: set `F`
- **Device targets**: set `D`

Device with `(fleet_id = f, id = d)` matches iff:
- `F` empty and `D` empty → **global** (match)
- `F` non-empty and `D` non-empty → **(f ∈ F) AND (d ∈ D)**
- `F` non-empty and `D` empty → **(f ∈ F)**
- `F` empty and `D` non-empty → **(d ∈ D)**

> This guarantees: **“only specific devices of a fleet must get the update if device IDs are set; if device IDs empty then all devices of the selected fleet(s).”**

### 4.3 Rollout Promotion
- If a rollout is `scheduled` and `start_at <= now`, the server flips it to `running` lazily during heartbeat enqueue (best-effort, not transactional across devices).

### 4.4 Throttling
- `throttleSeconds` in heartbeat response is currently `0` (no server pushback). It may be extended to implement **per-rollout** or **per-tenant** pacing later.

---

## 5) Admin / UI Flows

### 5.1 Packages
- **List** (`/packages`): shows `ID`, `Tenant`, `Name`, `Description`, `Versions`, `Latest`, `Size` (aggregate or latest size).
- **Upload** (`POST /packages/upload`):
  - Form fields: `tenant_id`, `name`, `version` (optional; derived from filename if omitted), `file`.
  - Artifact is stored under `ARTIFACTS_ROOT/<tenant>/<package_id>/<version>.<ext>`.
  - A corresponding `PackageVersion` row is **upserted** (same `<package_id, semver>` updates the path/hash/size).
  - **Delete Package** removes all `PackageVersion` rows **and** their artifact files on disk.

### 5.2 Rollouts
- **Create** (`/rollouts/new`):
  - Select `tenant`, `package`, `version`, `start_at`, `status` (implicitly `scheduled` initially).
  - **Target Fleets** (comma-separated ints) and **Target Device IDs** (comma-separated ints).
  - **Device Picker** panel (`/devices.json`) can append device IDs into the field and supports pagination/search (online-only filter by last seen).
- **View** (`/rollouts/<id>`): status counters strictly by `rollout_id`, table of devices with joined device meta.
- **Edit** / **Pause** / **Resume** / **Cancel** / **Delete** supported.

---

## 6) Artifacts

### 6.1 Storage
`ARTIFACTS_ROOT` (default `instance/artifacts`) with deterministic layout:
```
ARTIFACTS_ROOT/<tenant_id>/<package_id>/<semver>.<ext>
```

### 6.2 Stream/Range Support
`stream_file(path)` implements:
- Full responses (`200 OK`) with `Content-Length`.
- `Range` header support with `206 Partial Content`, `Content-Range`, `Accept-Ranges: bytes`.
- `416` if start offset is beyond EOF.

### 6.3 Hash & Size
On upload:
- `hash_sha256` is computed and stored in `package_version.hash_sha256`.
- `size_bytes` in `package_version.size_bytes`.

---

## 7) Simulator Scripts (Reference)

### 7.1 Single-agent Simulator
- Registers an agent under a fleet, heartbeats once or periodically, downloads an artifact, and posts results.
- Uses environment vars: `BASE`, `API_KEY`, `PACKAGE_ID`, `VERSION`, `FLEET_ID`.

### 7.2 Multi-device Load Script
- Loops over `--count`, registers `agent-<n>`, heartbeats, downloads artifact to a temp dir, posts result.
- Supports `--fail "3,5,7"` to mark specific indexes as failed.

---

## 8) Error Codes & Payloads

Common errors returned as JSON with appropriate HTTP status:

| HTTP | Body Example | Meaning |
|------|--------------|---------|
| 400 | `{"error":"hostname_and_fleetId_required"}` | Missing registration fields |
| 401 | `{"error":"unauthorized"}` | Missing/invalid API key |
| 403 | `{"error":"forbidden"}` | Key lacks `agents` scope or wrong tenant |
| 404 | `{"error":"device_not_found"}` | Heartbeat for non-tenant device |
| 404 | `{"error":"package_version_not_found"}` | Download for unknown `<package_id>/<semver>` |
| 416 | _no JSON_ | Bad `Range` header |

Server may also respond `429 Too Many Requests` if rate limits are exceeded (Flask-Limiter).

---

## 9) Security Notes

- API keys must be transported over HTTPS in production.
- CORS is disabled by default; agents are server-to-server.
- Artifact path is never derived from uncontrolled input; server writes to a temp file and renames atomically.
- Deletes remove DB rows and unlink artifact files; missing files are ignored (best-effort).

---

## 10) Example Agent Flow (End‑to‑End)

1. **Register**
   ```bash
   curl -sS -H "X-API-Key: $KEY" -H "Content-Type: application/json"      -X POST https://server/api/agents/register      -d '{"hostname":"agent-001","fleetId":1}'
   # → {"deviceId":24,"status":"idle"}
   ```

2. **Heartbeat (enqueue + action)**
   ```bash
   curl -sS -H "X-API-Key: $KEY" -H "Content-Type: application/json"      -X POST https://server/api/agents/heartbeat      -d '{"deviceId":24,"agentVersion":"1.2.0","osVersion":"Windows 11"}'
   # → {"actions":[{"action":"install","packageId":1,"version":"1.0.1"}],"throttleSeconds":0}
   ```

3. **Download**
   ```bash
   curl -H "X-API-Key: $KEY" -o ./pkg.zip https://server/api/updates/1/1.0.1
   ```

4. **Install (client-side)** → run scripts / verify hash / etc.

5. **Report Result**
   ```bash
   curl -sS -H "X-API-Key: $KEY" -H "Content-Type: application/json"      -X POST https://server/api/agents/install-results      -d '{"deviceId":24,"packageId":1,"version":"1.0.1","status":"succeeded","message":"ok"}'
   # → {"ok":true}
   ```

---

## 11) Backward / Forward Compatibility

- New optional fields are added conservatively; unknown JSON keys **must be ignored** by the agent.
- Status strings are normalized server-side to preserve compatibility.
- Target matching has been **tightened** (intersection when both fleets and devices set). Old agents are unaffected; behavior is fully server-side.

---

## 12) Changelog

- **v1.2 (2025‑10‑02)**: Intersection target rules; heartbeat stricter pending lookup; orphan pending cleanup; packages upload with explicit version; device picker JSON; improved artifact streaming headers.
- **v1.1 (2025‑10‑01)**: Added `/api/updates/<id>/<semver>`; basic rollouts; heartbeat auto‑enqueue; install-results normalization.
- **v1.0 (2025‑09‑30)**: Initial registration/heartbeat/results protocol.

---

## 13) Glossary

- **Due rollout**: rollout with `status in [scheduled, running]` and `start_at <= now`.
- **Pending installation**: a to-be-installed instruction for a specific `(device, package, version)`.
- **Applicable pending**: pending tied to a due rollout **and** matching targets per §4.2.

---

## 14) Contact Points for Integration

- **Agent to Server**: JSON over HTTPS with `X-API-Key`.
- **Artifacts**: Large binary ZIP download with HTTP range support.
- **Support Scripts**: See `update-agent-sim.sh` and the multi-device simulator for reference curl flows.

# Admin API

This document describes the **Admin-only** HTTP API exposed under the prefix **`/api/admin`**.  
These endpoints require the global admin key and are intended for platform operators (not tenant end-users).

---

## Authentication

Every request **must** include a valid global admin key using **one** of the following headers:

- `X-Admin-Key: <your-admin-key>`
- `Authorization: Bearer <your-admin-key>`

If the key is missing or invalid, the API returns `401 Unauthorized`.

> The decorator used is `@require_global_admin_key`.

---

## Conventions

- **Base URL**: `/api/admin`
- **Content-Type**: `application/json` for requests with a body.
- **Timestamps & numbers**: Monetary values are returned in both **cents** (integers) and **major units** (floats, e.g., EUR).
- **Errors** are JSON objects:
  ```json
  { "error": "<code>", "message": "<human readable>" }
  ```
- **Idempotency**: Enabling/disabling a resource twice is safe; you’ll get the current state.

---

## Endpoints

### 1) Tenants

#### Create tenant
`POST /api/admin/tenants`

Create or return an existing tenant.

**Body**
```json
{
  "name": "IBSOFT",
  "slug": "ibsoft",            // optional; auto-generated if missing
  "active": true               // optional; default true
}
```

**Responses**
- `201 Created`
  ```json
  { "id": 1, "name": "IBSOFT", "slug": "ibsoft", "status": "active" }
  ```
- `200 OK` (if a tenant with same name already exists)
  ```json
  { "id": 1, "name": "IBSOFT", "slug": "ibsoft", "status": "active" }
  ```
- `400` if `name` missing.

---

#### List tenants
`GET /api/admin/tenants?status=active|disabled`

**Response**
```json
[
  { "id": 1, "name": "IBSOFT", "slug": "ibsoft", "status": "active" },
  { "id": 2, "name": "UNIXFOR", "slug": "unixfor", "status": "active" }
]
```

---

#### Enable tenant
`PATCH /api/admin/tenants/{tenant_id}/enable`

**Response**
```json
{ "id": 1, "status": "active" }
```

#### Disable tenant
`PATCH /api/admin/tenants/{tenant_id}/disable`

**Response**
```json
{ "id": 1, "status": "disabled" }
```

#### Delete tenant
`DELETE /api/admin/tenants/{tenant_id}`

**Response**
```json
{ "status": "deleted", "id": 1 }
```

---

### 2) Users

#### Create user
`POST /api/admin/users`

**Body**
```json
{
  "email": "demo@demo.com",
  "full_name": "Demo User",          // optional
  "password": "TempPass123!",        // optional; a temp password is generated if omitted
  "tenant_id": 1,
  "active": true                     // optional; default true
}
```

**Responses**
- `201 Created`
  ```json
  {
    "id": 10,
    "email": "demo@demo.com",
    "tenant_id": 1,
    "status": "active",
    "temp_password": "generated-if-you-didnt-supply"   // null if you supplied one
  }
  ```
- `400` if required fields are missing
- `404` if tenant not found
- `409` if email already exists

---

#### List users
`GET /api/admin/users?tenant_id=1&status=active|disabled`

**Response**
```json
[
  {
    "id": 10,
    "email": "demo@demo.com",
    "full_name": "Demo User",
    "status": "active",
    "tenant_id": 1,
    "tenant_name": "IBSOFT",
    "tenant_slug": "ibsoft"
  }
]
```

#### Enable/Disable user
`PATCH /api/admin/users/{user_id}/enable`  
`PATCH /api/admin/users/{user_id}/disable`

**Response**
```json
{ "id": 10, "status": "active" }
```

#### Delete user
`DELETE /api/admin/users/{user_id}`

**Response**
```json
{ "status": "deleted", "id": 10 }
```

---

### 3) Billing (Admin)

These endpoints manage a tenant’s **current cost** and **rate**.  
They **do not** require a UI session; the tenant is specified in the path.

#### Get tenant billing (current cost & rate)
`GET /api/admin/tenants/{tenant_id}/billing`

**Response**
```json
{
  "tenant_id": 1,
  "tenant_name": "IBSOFT",
  "currency": "eur",
  "rate_cents": 38,
  "rate": 0.38,
  "outstanding_cents": 228,
  "outstanding": 2.28
}
```

- `404` if tenant not found.

---

#### Reset tenant current cost (mark as paid)
`POST /api/admin/tenants/{tenant_id}/billing/reset`

Resets `outstanding_cents` to **0** when a payment is reconciled.

**Body** (optional)
```json
{
  "reason": "Invoice INV-2025-001 paid",
  "by": "operator@company.com"
}
```

**Response**
```json
{
  "ok": true,
  "tenant_id": 1,
  "previous_outstanding_cents": 228,
  "new_outstanding_cents": 0
}
```

- `404` if tenant not found.

---

#### Set tenant rate (optional helper)
`POST /api/admin/tenants/{tenant_id}/billing/rate`

Sets the rate per device.

**Body** (one of the two forms)
```json
{ "rate_eur": 0.38 }
```
or
```json
{ "rate_cents": 38 }
```

**Response**
```json
{ "ok": true, "tenant_id": 1, "rate_cents": 38, "rate": 0.38 }
```

- `400` if both are missing or invalid
- `404` if tenant not found

> Note: This is a convenience wrapper over the internal billing update. If you’re already using a separate admin UI to set rates, you can skip this endpoint.

---

## cURL Examples

> Replace `ADMIN_KEY` with your real key.

### Create tenant
```bash
curl -sS -X POST http://localhost:8080/api/admin/tenants   -H 'X-Admin-Key: ADMIN_KEY'   -H 'Content-Type: application/json'   -d '{"name":"IBSOFT","slug":"ibsoft","active":true}'
```

### List tenants
```bash
curl -sS http://localhost:8080/api/admin/tenants   -H 'X-Admin-Key: ADMIN_KEY'
```

### Create user
```bash
curl -sS -X POST http://localhost:8080/api/admin/users   -H 'X-Admin-Key: ADMIN_KEY'   -H 'Content-Type: application/json'   -d '{"email":"demo@demo.com","tenant_id":1,"full_name":"Demo User"}'
```

### Get tenant billing
```bash
curl -sS http://localhost:8080/api/admin/tenants/1/billing   -H 'X-Admin-Key: ADMIN_KEY'
```

### Reset tenant current cost to 0
```bash
curl -sS -X POST http://localhost:8080/api/admin/tenants/1/billing/reset   -H 'X-Admin-Key: ADMIN_KEY'   -H 'Content-Type: application/json'   -d '{"reason":"Invoice INV-2025-001 paid","by":"ops@company.com"}'
```

### Set tenant rate to €0.38
```bash
curl -sS -X POST http://localhost:8080/api/admin/tenants/1/billing/rate   -H 'X-Admin-Key: ADMIN_KEY'   -H 'Content-Type: application/json'   -d '{"rate_eur":0.38}'
```

---

## Status Codes

- `200 OK` — Success for reads/updates.
- `201 Created` — Resource created.
- `400 Bad Request` — Missing or invalid parameters.
- `401 Unauthorized` — Missing/invalid admin key.
- `403 Forbidden` — Key valid but not authorized (rare with this key).
- `404 Not Found` — Resource does not exist.
- `415 Unsupported Media Type` — Missing `Content-Type: application/json` when body is expected.
- `409 Conflict` — Unique constraint conflict (e.g., duplicate email).

---

## Security Notes

- The global admin key is highly privileged. Store it securely (not in client-side code).
- Prefer running these calls from trusted backoffice services or ops scripts.
- Consider network-level protections (VPN/allowlist) for `/api/admin`.

---

## Versioning

- Current version: **v1** (unversioned paths).  
- Backward-compatible additions may appear without path changes.  
- Breaking changes will be announced and versioned if introduced.

---

## Changelog

- **2025-10-06**
  - Added **tenant billing** admin endpoints:
    - `GET /api/admin/tenants/{id}/billing`
    - `POST /api/admin/tenants/{id}/billing/reset`
    - `POST /api/admin/tenants/{id}/billing/rate` (helper)
  - Existing **tenants** and **users** endpoints documented.




