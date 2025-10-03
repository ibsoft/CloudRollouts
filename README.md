# CloudRollouts

Multi-tenant update server για στόλους Windows/Linux. Admin UI (Bootstrap), agent API, artifacts με Range streaming, health/ready, metrics, Swagger, rate-limits, scheduler.



<img width="1920" height="1020" alt="image" src="https://github.com/user-attachments/assets/7807194d-b40b-4910-bdd4-00e9b90ad843" />

<img width="1920" height="1020" alt="image" src="https://github.com/user-attachments/assets/5a91cdfa-7057-4a63-9b1b-6168b2317ee5" />


<img width="1920" height="1020" alt="image" src="https://github.com/user-attachments/assets/a5c36257-79a6-41ed-af14-1d84cf919cfd" />

<img width="1920" height="1020" alt="image" src="https://github.com/user-attachments/assets/4f0ff1a3-0b7c-46e7-a57e-18a049b23eca" />

<img width="1920" height="1020" alt="image" src="https://github.com/user-attachments/assets/85797c14-6a8b-4e18-a78b-8bfaa9ec8ceb" />

<img width="1920" height="1020" alt="image" src="https://github.com/user-attachments/assets/71203cbb-df57-49c1-9b61-aab47d6da57a" />


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


