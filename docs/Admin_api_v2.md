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
