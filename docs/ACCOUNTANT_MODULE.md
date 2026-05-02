**Accountant Module API**

This document describes the `Accountant` module endpoints exposed by the NestJS backend at the `/accountant` prefix. The controller proxies to the external AI Accountant service; frontends should call these backend endpoints (do NOT call the AI Accountant service directly).

**Auth**: Most endpoints require an authenticated backend user (JWT) and tenant context. Attach a valid `Authorization: Bearer <jwt>` header when calling protected endpoints. Health endpoint is public.

**Environment**

- `AI_ACCOUNTANT_URL` — upstream AI Accountant base URL (default: http://localhost:8000)
- `AI_ACCOUNTANT_API_KEY` — API key added to upstream requests as `X-API-Key` (required for integration)
- `AI_ACCOUNTANT_TIMEOUT_MS` — HTTP timeout for upstream calls (ms)

Common error wrapper returned by this backend for service unavailability (HTTP 503):

```json
{
  "message": "AI Accountant service is unavailable",
  "timestamp": "2026-05-01T12:00:00.000Z",
  "status": "unavailable",
  "service": "ai-accountant"
}
```

---

**1) Create Accounting Job**

POST /accountant/jobs

Auth: required (JWT)

Request body (JSON):

```json
{
  "businessId": "60d5ecb8b6f3c72e7c8e4a5b",
  "periodStart": "2024-01-01T00:00:00Z",
  "periodEnd": "2024-01-31T23:59:59Z"
}
```

Notes/validation:

- `periodStart` and `periodEnd` must be ISO 8601 datetimes.
- Period length should not exceed 365 days (the service will validate and return 400 if invalid).

Success response (HTTP 201):

```json
{
  "message": "Accounting job created. Processing will begin shortly.",
  "timestamp": "2026-05-01T12:00:00.000Z",
  "job": {
    "taskId": "60d5ecb8b6f3c72e7c8e4a5b_20240101_20240131",
    "status": "pending",
    "message": "Accounting job created for period 2024-01-01 to 2024-01-31",
    "estimatedSeconds": 59,
    "estimatedCompletion": "2024-01-01T00:00:59Z"
  }
}
```

Other possible status responses from upstream when creating:

- `processing` — job already in progress
- `completed` — job already completed (use GET results)

Errors:

- 400 Bad Request — invalid period (exceeds 365 days or end before start)
- 401/403 — missing/invalid JWT or backend-level auth
- 404 Not Found — business not found
- 500 — backend or upstream error

---

**2) List Accounting Jobs**

GET /accountant/jobs?businessId={businessId}&status={status}&limit={limit}

Auth: required (JWT)

Query parameters:

- `businessId` (required) — Business ID to list jobs for
- `status` (optional) — Filter by status (`pending`, `processing`, `completed`, `failed`)
- `limit` (optional) — Max results (1-100, default 10)

Success response (HTTP 200):

```json
{
  "message": "Accounting jobs retrieved successfully",
  "timestamp": "2026-05-01T12:00:00.000Z",
  "jobs": [
    {
      "taskId": "60d5ecb8b6f3c72e7c8e4a5b_20240101_20240131",
      "businessId": "60d5ecb8b6f3c72e7c8e4a5b",
      "periodStart": "2024-01-01T00:00:00Z",
      "periodEnd": "2024-01-31T23:59:59Z",
      "status": "completed",
      "progressPercent": 100,
      "startedAt": "2024-04-19T10:30:00Z",
      "completedAt": "2024-04-19T10:31:15Z",
      "errorMessage": null,
      "journalEntriesCount": 42,
      "reportsGenerated": 3,
      "estimatedSeconds": 120,
      "estimatedCompletion": "2024-04-19T10:32:00Z",
      "estimatedTimeRemaining": 0
    }
  ],
  "total": 1
}
```

Errors:

- 404 Not Found — business not found

---

**3) Get Job Status**

GET /accountant/jobs/{taskId}?businessId={businessId}

Auth: required (JWT)

Notes: This endpoint returns a status-shaped payload while a job is pending/processing. When the job is completed, use the results endpoint to retrieve full accounting outputs.

Success response (HTTP 200):

```json
{
  "message": "Job status retrieved successfully",
  "timestamp": "2026-05-01T12:00:00.000Z",
  "job": {
    "taskId": "...",
    "businessId": "...",
    "periodStart": "2024-01-01T00:00:00Z",
    "periodEnd": "2024-01-31T23:59:59Z",
    "status": "processing",
    "progressPercent": 55,
    "startedAt": "2024-04-19T10:30:00Z",
    "completedAt": null,
    "errorMessage": null,
    "journalEntriesCount": 0,
    "reportsGenerated": 0,
    "estimatedSeconds": 120,
    "estimatedCompletion": "2024-04-19T10:32:00Z",
    "estimatedTimeRemaining": 65
  }
}
```

Errors:

- 404 Task not found — task id or business mismatch

---

**4) Get Job Results (Full)**

GET /accountant/jobs/{taskId}/results?businessId={businessId}

Auth: required (JWT)

Returns the complete accounting results once the job status is `completed`. If the job is not completed yet, this endpoint returns a 400 error with a helpful message.

Success response (HTTP 200):

```json
{
  "message": "Job results retrieved successfully",
  "timestamp": "2026-05-01T12:00:00.000Z",
  "results": {
    "taskId": "...",
    "businessId": "...",
    "periodStart": "2024-01-01T00:00:00Z",
    "periodEnd": "2024-01-31T23:59:59Z",
    "status": "completed",

    "totalRevenue": 12500.0,
    "totalExpenses": 5000.0,
    "grossProfit": 7500.0,
    "netProfit": 6750.0,
    "accountsReceivable": 2500.0,
    "accountsPayable": 1000.0,
    "cashPosition": 8500.0,

    "taxCalculations": [
      {
        "taxType": "VAT",
        "jurisdiction": "Tunisia",
        "taxableAmount": 12500.0,
        "taxRate": 0.19,
        "taxAmount": 2375.0,
        "notes": ""
      }
    ],

    "aiInsights": "Revenue up 15% vs last month. Review A/R aging.",
    "recommendations": ["Follow up on 3 overdue invoices"],

    "anomaliesDetected": [
      {
        "id": "A-1001",
        "type": "duplicate_invoice",
        "severity": "medium",
        "description": "Detected duplicate invoices INV-2024-007 and INV-2024-008...",
        "detectedAt": "2024-01-20T09:12:34Z",
        "affectedRecords": ["INV-2024-007", "INV-2024-008"],
        "suggestedAction": "Review the invoices..."
      }
    ],

    "reports": [
      {
        "reportType": "P&L",
        "periodStart": "2024-01-01T00:00:00Z",
        "periodEnd": "2024-01-31T23:59:59Z",
        "data": { "profit": 6750 }
      }
    ],

    "journalEntries": [
      {
        "date": "2024-01-15T00:00:00Z",
        "account": "Accounts Receivable",
        "debit": 12500.0,
        "credit": 0.0,
        "description": "Invoice INV-2024-001",
        "invoiceId": "INV-2024-001",
        "metadata": {}
      }
    ],

    "totalJournalEntries": 42
  }
}
```

Errors:

- 400 Bad Request — job not completed yet (response includes message stating current status)
- 404 Not Found — task not found or business not found

---

**5) Get Persisted Tax Summary**

GET /accountant/taxes?businessId={businessId}&year={year}

Auth: required (JWT)

Query params:

- `businessId` required
- `year` optional (defaults to current year)

Success response (HTTP 200):

```json
{
  "message": "Tax summary retrieved successfully",
  "timestamp": "2026-05-01T12:00:00.000Z",
  "taxes": {
    "businessId": "60d5ecb8b6f3c72e7c8e4a5b",
    "businessName": "Acme Corp",
    "year": 2024,
    "currency": "TND",
    "summary": {
      "annualVatTotal": 28500.0,
      "annualCorporateTax": 13500.0,
      "annualWithholdingTax": 2250.0,
      "totalTaxLiability": 44250.0
    },
    "vatBreakdown": {
      "standardRate19Percent": 28500.0,
      "reducedRate13Percent": 0.0,
      "reducedRate7Percent": 0.0
    },
    "monthlyDetails": [
      {
        "month": 1,
        "period": "01/2024",
        "vatStandard19": 2375.0,
        "vatReduced13": 0.0,
        "vatReduced7": 0.0,
        "vatTotal": 2375.0,
        "taxableIncome": 7500.0,
        "corporateTaxDue": 1125.0,
        "withholdingTax": 187.5,
        "totalTaxLiability": 3631.25,
        "dueDate": "2024-02-28T00:00:00Z"
      }
    ],
    "taxCalendar": [
      {
        "period": "01/2024",
        "dueDate": "2024-02-28T00:00:00Z",
        "description": "VAT due for January 2024"
      }
    ],
    "notes": ["VAT (TVA) is due by the 28th of the following month"],
    "createdAt": "2024-02-01T09:05:00Z",
    "lastUpdatedAt": "2024-02-01T09:05:00Z"
  }
}
```

Errors:

- 404 Not Found — tax results not found for given business/year

---

**6) Calculate & Persist Tax Summary**

POST /accountant/taxes/calculate?businessId={businessId}&year={year}

Auth: required (JWT)

No request body.

Success responses:

- If the endpoint returns the persisted tax summary (JSON): same shape as GET `/taxes` above.
- If the endpoint returns a location/pending acknowledgement (no JSON body), the backend returns a simple result object:

```json
{
  "message": "Tax calculation started/persisted",
  "businessId": "60d5ecb8b6f3c72e7c8e4a5b",
  "year": 2024
}
```

Errors:

- 400 Bad Request — invalid year
- 404 Not Found — business not found

---

**Health**

GET /accountant/health

Public (no JWT required).

Success (AI Accountant reachable):

```json
{
  "message": "AI Accountant service is available",
  "timestamp": "2026-05-01T12:00:00.000Z",
  "status": "available",
  "service": "ai-accountant"
}
```

If the backend cannot reach the AI Accountant upstream, this endpoint returns HTTP 503 with the unavailability payload shown at the top of this document.

---

Notes & Integration Tips

- Frontend should always call these backend endpoints; the backend adds the `X-API-Key` header when calling the AI Accountant upstream.
- Use `POST /accountant/jobs` to create an idempotent task (taskId is derived from businessId + period range). Poll `GET /accountant/jobs/{taskId}` for status and `GET /accountant/jobs/{taskId}/results` once status is `completed`.
- Monetary values in responses are JSON numbers (floats). Timestamps are UTC ISO 8601 strings.
- API responses from this backend are wrapped with `message`/`timestamp` fields for telemetry and clarity. Inspect the `results`/`job`/`taxes` properties for payload data.

If you'd like, I can also add TypeScript client helpers (service wrappers) or OpenAPI examples based on these types.
