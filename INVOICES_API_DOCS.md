# Invoices API Documentation

## Overview

The Invoices API provides endpoints for managing invoices in a multi-tenant system. Invoices can be **issued** by businesses and **received** by businesses or individuals. Supports both individual invoice creation and bulk import from CSV/Excel files.

**Base URL:** `/invoices`  
**Authentication:** Bearer Token (JWT)

### Key Features

- Create and manage invoices with flexible recipient types (platform businesses, individuals, external contacts)
- Bulk import invoices from CSV or Excel files
- Track invoice lifecycle through state transitions (DRAFT → ISSUED → PAID, etc.)
- View invoices issued by your business or received by you
- Email notifications and WebSocket real-time updates
- Cross-tenant invoice discovery and receipt tracking

### Architecture

The invoices system uses a **three-service architecture**:

- **InvoiceIssuanceService**: Creates, updates, and manages invoices issued by your business (stored in tenant database)
- **InvoiceReceiptService**: Allows viewing and managing invoices received by your business or individual account (synced from issuer's database)
- **RecipientResolutionService**: Background service for identity resolution of external recipients
- **InvoiceImportService**: Bulk import invoices from CSV/Excel files

**Database Storage:**

- Invoices are stored in the **issuer's tenant database** (authoritative source)
- InvoiceReceipts are synced to the **platform database** for cross-tenant recipient discoverability
- Recipient emails are normalized (lowercase) for consistent matching

### Magic Search Feature

The system provides **automatic recipient lookup** to reduce frontend complexity. When creating an invoice with `PLATFORM_BUSINESS` or `PLATFORM_INDIVIDUAL` recipient type:

- **If `platformId` is provided**: Uses the provided ID (no search performed)
- **If `platformId` is NOT provided**:
  - System automatically searches for a matching business or user by email
  - For `PLATFORM_BUSINESS`: Searches the Business collection for matching email
  - For `PLATFORM_INDIVIDUAL`: Searches the User collection for matching email
  - If found: Auto-populates `platformId` with the matched ID → `resolutionStatus` = RESOLVED
  - If not found: Returns **400 Bad Request** asking to provide explicit `platformId` or use `EXTERNAL` type
- **For `EXTERNAL` recipients**: No search performed, email-only recipient accepted as-is

**Benefits:**

- Reduce API calls by eliminating separate business/user lookup requests
- Automatic identity resolution improves data consistency
- Frontend can send just email for known platform recipients
- Clear error messages guide users on missing recipient resolution

**Examples:**

```javascript
// PLATFORM_BUSINESS: Without platformId (auto-search by email)
{
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "email": "billing@company.com"
    // platformId auto-resolved if business exists with this email
  }
}

// PLATFORM_BUSINESS: With explicit platformId (no search)
{
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "platformId": "biz-123",
    "email": "billing@company.com"
    // platformId used directly, no search performed
  }
}

// EXTERNAL: Email-only (no search)
{
  "recipient": {
    "type": "EXTERNAL",
    "email": "external@unknown.com",
    "displayName": "External Company"
    // No search, accepted as external recipient
  }
}
```

---

## Tenant Context & businessId Requirements

**All endpoints under "ISSUER ENDPOINTS" and "IMPORT ENDPOINTS" require authentication in a tenant context.** They use `TenantContextGuard` to resolve which business's database to query. You must provide `businessId` to identify the tenant context:

| Endpoint Group                                | Method      | Requires businessId | Where to Send                           |
| --------------------------------------------- | ----------- | ------------------- | --------------------------------------- |
| **Issuer** (Create, List, Update, Transition) | POST, PATCH | ✓ Yes               | **Request Body** (JSON)                 |
| **Issuer** (Get/List)                         | GET         | ✓ Yes               | **Query Parameter** (`?businessId=...`) |
| **Recipient - Business** (Get/List)           | GET         | ✓ Yes               | **Query Parameter** (`?businessId=...`) |
| **Recipient - Individual** (Get/List)         | GET         | ✗ No                | N/A (uses current user context)         |
| **Import**                                    | POST        | ✓ Yes               | **Form Data** (multipart)               |

---

## Enums

### InvoiceStatus

```
DRAFT       - Invoice prepared but not yet published
ISSUED      - Published to recipient
VIEWED      - Recipient has seen it
PAID        - Full payment received
PARTIAL     - Partial payment received
OVERDUE     - Past due date without full payment
DISPUTED    - Recipient disputes the amount
VOIDED      - Issuer voided the invoice
ARCHIVED    - Kept for historical record
```

### InvoiceRecipientType

```
PLATFORM_BUSINESS      - Registered business on platform
                         Magic search: Searches Business collection by email if platformId not provided
PLATFORM_INDIVIDUAL    - Registered user on platform
                         Magic search: Searches User collection by email if platformId not provided
EXTERNAL               - External contact (not on platform)
                         No magic search: Email-only recipient, no platformId required
```

### RecipientResolutionStatus

```
RESOLVED       - Recipient identity linked to platform user/business
PENDING        - Recipient exists but identity not yet resolved
CLAIMED        - External recipient claimed their identity
NEVER_RESOLVED - External recipient never joined platform
```

---

## ISSUER ENDPOINTS

These endpoints allow the business that issued an invoice to manage it.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`, `BusinessRolesGuard`  
**Required Roles:** `OWNER`, `ADMIN`

**Tenant Context:** `TenantContextGuard` reads `businessId` from the request. **Send `businessId` in the request body** for all POST/PATCH endpoints in this section.

---

### 1. Create Invoice (Draft)

```http
POST /invoices
```

**Description:** Create a new invoice in DRAFT state. Invoice is not visible to recipient until transitioned to ISSUED.

**Magic Search Behavior:**

- If creating with `PLATFORM_BUSINESS` or `PLATFORM_INDIVIDUAL` type but **without** `platformId`, the system automatically searches for a matching business or user by email
- Search succeeds → `platformId` auto-populated, `resolutionStatus` = `RESOLVED`
- Search fails → Returns **400 Bad Request** with guidance
- For `EXTERNAL` recipients, no search performed; email-only is accepted

See **Magic Search Feature** section above for detailed examples.

**Request Body (Example 1: With Magic Search):**

```json
{
  "businessId": "biz-123",
  "invoiceNumber": "INV-2025-001",
  "issuedDate": "2025-04-04T00:00:00Z",
  "dueDate": "2025-05-04T00:00:00Z",
  "currency": "USD",
  "description": "Services for March 2025",
  "paymentTerms": "NET 30",
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "email": "billing@company.com"
  },
```

**Request Body (Example 2: With Explicit platformId):**

```json
{
  "businessId": "biz-123",
  "invoiceNumber": "INV-2025-001",
  "issuedDate": "2025-04-04T00:00:00Z",
  "dueDate": "2025-05-04T00:00:00Z",
  "currency": "USD",
  "description": "Services for March 2025",
  "paymentTerms": "NET 30",
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "platformId": "business-id-123",
    "email": "billing@company.com"
  },
  "lineItems": [
    {
      "productId": "prod-123",
      "productName": "Consulting Services",
      "quantity": 10,
      "unitPrice": 150.0,
      "description": "20 hours of consulting"
    },
    {
      "productId": "prod-456",
      "productName": "Software License",
      "quantity": 1,
      "unitPrice": 500.0
    }
  ]
}
```

**Success Response (201 Created):**

```json
{
  "id": "invoice-60d5ec49c1234567890abcd1",
  "issuerBusinessId": "biz-123",
  "invoiceNumber": "INV-2025-001",
  "status": "DRAFT",
  "totalAmount": 2000.0,
  "currency": "USD",
  "amountPaid": 0,
  "issuedDate": "2025-04-04T00:00:00Z",
  "dueDate": "2025-05-04T00:00:00Z",
  "description": "Services for March 2025",
  "paymentTerms": "NET 30",
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "platformId": "business-id-123",
    "email": "billing@company.com",
    "resolutionStatus": "RESOLVED",
    "lastResolutionAttempt": "2025-04-04T10:00:00Z"
  },
  "lineItems": [
    {
      "id": "item-60d5ec49c1234567890abcd1",
      "productId": "prod-123",
      "productName": "Consulting Services",
      "quantity": 10,
      "unitPrice": 150.0,
      "amount": 1500.0,
      "description": "20 hours of consulting"
    },
    {
      "id": "item-60d5ec49c1234567890abcd2",
      "productId": "prod-456",
      "productName": "Software License",
      "quantity": 1,
      "unitPrice": 500.0,
      "amount": 500.0
    }
  ],
  "createdBy": "user-123",
  "createdAt": "2025-04-04T10:30:00Z",
  "updatedAt": "2025-04-04T10:30:00Z"
}
```

**Error Responses:**

- **400 Bad Request** - Invalid input, duplicate invoice number, or recipient not found

  ```json
  {
    "statusCode": 400,
    "message": "Invoice number already exists for this business",
    "error": "Bad Request"
  }
  ```

- **400 Bad Request** - Recipient not found (magic search failed)

  ```json
  {
    "statusCode": 400,
    "message": "Cannot find PLATFORM_BUSINESS recipient with email billing@unknown.com. Please provide platformId or create the invoice as type EXTERNAL.",
    "error": "Bad Request"
  }
  ```

- **403 Forbidden** - Insufficient permissions
- **401 Unauthorized** - Missing or invalid token

---

### 2. List Issued Invoices

```http
GET /invoices/issued?businessId=biz-123&status=ISSUED&page=1&limit=10
```

**Description:** Retrieve all invoices issued by the current business.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`, `BusinessRolesGuard`

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `businessId` | string | Yes | Your business ID (required for tenant context) |
| `status` | string | No | Filter by status (DRAFT, ISSUED, PAID, etc.) |
| `page` | number | No | Page number (default: 1) |
| `limit` | number | No | Items per page (default: 10) |

**Success Response (200 OK):**

```json
{
  "invoices": [
    {
      "id": "invoice-60d5ec49c1234567890abcd1",
      "issuerBusinessId": "biz-123",
      "invoiceNumber": "INV-2025-001",
      "status": "ISSUED",
      "totalAmount": 2000.0,
      "currency": "USD",
      "amountPaid": 0,
      "issuedDate": "2025-04-04T00:00:00Z",
      "dueDate": "2025-05-04T00:00:00Z",
      "recipient": {
        "type": "PLATFORM_BUSINESS",
        "platformId": "business-id-123",
        "email": "billing@company.com",
        "resolutionStatus": "RESOLVED"
      },
      "lineItems": [],
      "createdAt": "2025-04-04T10:30:00Z",
      "updatedAt": "2025-04-04T11:00:00Z"
    }
  ],
  "total": 25,
  "page": 1,
  "limit": 10,
  "totalPages": 3
}
```

---

### 3. Get Single Issued Invoice

```http
GET /invoices/issued/:id?businessId=biz-123
```

**Description:** Retrieve details of a specific invoice issued by your business.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`, `BusinessRolesGuard`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Invoice ID |

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `businessId` | string | Yes | Your business ID (required for tenant context) |

**Success Response (200 OK):**

```json
{
  "id": "invoice-60d5ec49c1234567890abcd1",
  "issuerBusinessId": "biz-123",
  "invoiceNumber": "INV-2025-001",
  "status": "ISSUED",
  "totalAmount": 2000.0,
  "currency": "USD",
  "amountPaid": 0,
  "issuedDate": "2025-04-04T00:00:00Z",
  "dueDate": "2025-05-04T00:00:00Z",
  "description": "Services for March 2025",
  "paymentTerms": "NET 30",
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "platformId": "business-id-123",
    "email": "billing@company.com",
    "resolutionStatus": "RESOLVED",
    "lastResolutionAttempt": "2025-04-04T10:00:00Z"
  },
  "lineItems": [
    {
      "id": "item-60d5ec49c1234567890abcd1",
      "productId": "prod-123",
      "productName": "Consulting Services",
      "quantity": 10,
      "unitPrice": 150.0,
      "amount": 1500.0,
      "description": "20 hours of consulting"
    }
  ],
  "createdBy": "user-123",
  "lastModifiedBy": "user-123",
  "lastStatusChangeAt": "2025-04-04T11:00:00Z",
  "createdAt": "2025-04-04T10:30:00Z",
  "updatedAt": "2025-04-04T11:00:00Z"
}
```

**Error Responses:**

- **404 Not Found** - Invoice doesn't exist

  ```json
  {
    "statusCode": 404,
    "message": "Invoice not found",
    "error": "Not Found"
  }
  ```

- **403 Forbidden** - You don't own this invoice

---

### 4. Update Draft Invoice

```http
PATCH /invoices/issued/:id
```

**Description:** Update a DRAFT invoice. Once ISSUED, use state transitions instead. Only DRAFT invoices can be edited.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`, `BusinessRolesGuard`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Invoice ID |

**Request Body:**

```json
{
  "businessId": "biz-123",
  "description": "Updated description",
  "paymentTerms": "NET 45",
  "dueDate": "2025-05-19T00:00:00Z"
}
```

**Success Response (200 OK):**

```json
{
  "id": "invoice-60d5ec49c1234567890abcd1",
  "issuerBusinessId": "biz-123",
  "invoiceNumber": "INV-2025-001",
  "status": "DRAFT",
  "totalAmount": 2000.0,
  "currency": "USD",
  "amountPaid": 0,
  "issuedDate": "2025-04-04T00:00:00Z",
  "dueDate": "2025-05-19T00:00:00Z",
  "description": "Updated description",
  "paymentTerms": "NET 45",
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "platformId": "business-id-123",
    "email": "billing@company.com",
    "resolutionStatus": "RESOLVED"
  },
  "lineItems": [],
  "lastModifiedBy": "user-123",
  "createdAt": "2025-04-04T10:30:00Z",
  "updatedAt": "2025-04-04T12:00:00Z"
}
```

**Error Responses:**

- **400 Bad Request** - Cannot update non-draft invoice

  ```json
  {
    "statusCode": 400,
    "message": "Cannot update non-draft invoice",
    "error": "Bad Request"
  }
  ```

- **404 Not Found** - Invoice doesn't exist

---

### 5. Transition Invoice State

```http
POST /invoices/issued/:id/transition
```

**Description:** Change invoice status to a new state (e.g., DRAFT → ISSUED, ISSUED → PAID). Only valid state transitions are allowed.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`, `BusinessRolesGuard`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Invoice ID |

**Request Body:**

```json
{
  "businessId": "biz-123",
  "newStatus": "ISSUED",
  "reason": "Published to customer"
}
```

**For PAID/PARTIAL transitions, include amountPaid:**

```json
{
  "businessId": "biz-123",
  "newStatus": "PAID",
  "amountPaid": 2000.0,
  "reason": "Payment received via bank transfer"
}
```

**Success Response (200 OK):**

```json
{
  "id": "invoice-60d5ec49c1234567890abcd1",
  "issuerBusinessId": "biz-123",
  "invoiceNumber": "INV-2025-001",
  "status": "PAID",
  "totalAmount": 2000.0,
  "currency": "USD",
  "amountPaid": 2000.0,
  "issuedDate": "2025-04-04T00:00:00Z",
  "dueDate": "2025-05-04T00:00:00Z",
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "platformId": "business-id-123",
    "email": "billing@company.com",
    "resolutionStatus": "RESOLVED"
  },
  "lineItems": [],
  "lastModifiedBy": "user-123",
  "lastStatusChangeAt": "2025-04-04T15:30:00Z",
  "createdAt": "2025-04-04T10:30:00Z",
  "updatedAt": "2025-04-04T15:30:00Z"
}
```

**Error Responses:**

- **400 Bad Request** - Invalid state transition

  ```json
  {
    "statusCode": 400,
    "message": "Invalid transition from DRAFT to PAID",
    "error": "Bad Request"
  }
  ```

- **404 Not Found** - Invoice doesn't exist

---

## RECIPIENT ENDPOINTS

These endpoints allow businesses and individuals to view invoices sent to them.

**Authentication:** Bearer Token (JWT)

---

### 6. Get Invoices Received by Business

```http
GET /invoices/received/business?businessId=biz-123&status=ISSUED&page=1&limit=10
```

**Description:** Retrieve all invoices received by the current business from any issuer.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `businessId` | string | Yes | Your business ID (required for tenant context) |
| `status` | string | No | Filter by status |
| `page` | number | No | Page number (default: 1) |
| `limit` | number | No | Items per page (default: 10) |

**Success Response (200 OK):**

```json
{
  "receipts": [
    {
      "id": "receipt-60d5ec49c1234567890abcd1",
      "invoiceId": "invoice-60d5ec49c1234567890abcd1",
      "issuerTenantDatabaseName": "tenant-issuer-001",
      "issuerBusinessId": "biz-456",
      "issuerBusinessName": "ABC Corporation",
      "invoiceNumber": "INV-2025-001",
      "totalAmount": 2000.0,
      "currency": "USD",
      "issuedDate": "2025-04-04T00:00:00Z",
      "dueDate": "2025-05-04T00:00:00Z",
      "invoiceStatus": "ISSUED",
      "recipientViewed": false,
      "lastSyncedAt": "2025-04-04T10:30:00Z",
      "createdAt": "2025-04-04T10:30:00Z"
    }
  ],
  "total": 5,
  "page": 1,
  "limit": 10,
  "totalPages": 1
}
```

**Error Responses:**

- **403 Forbidden** - Invalid business context
- **401 Unauthorized** - Missing token

---

### 7. Get Invoices Received by Individual

```http
GET /invoices/received/individual?status=ISSUED&page=1&limit=10
```

**Description:** Retrieve all invoices received by the current user from any business.

**Required Guards:** `JwtAuthGuard`

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | Filter by status |
| `page` | number | No | Page number (default: 1) |
| `limit` | number | No | Items per page (default: 10) |

**Success Response (200 OK):**

```json
{
  "receipts": [
    {
      "id": "receipt-60d5ec49c1234567890abcd2",
      "invoiceId": "invoice-60d5ec49c1234567890abcd2",
      "issuerTenantDatabaseName": "tenant-issuer-002",
      "issuerBusinessId": "biz-789",
      "issuerBusinessName": "XYZ Services",
      "invoiceNumber": "INV-2025-002",
      "totalAmount": 500.0,
      "currency": "USD",
      "issuedDate": "2025-04-01T00:00:00Z",
      "dueDate": "2025-05-01T00:00:00Z",
      "invoiceStatus": "ISSUED",
      "recipientViewed": true,
      "recipientViewedAt": "2025-04-04T09:00:00Z",
      "lastSyncedAt": "2025-04-04T10:30:00Z",
      "createdAt": "2025-04-01T15:00:00Z"
    }
  ],
  "total": 3,
  "page": 1,
  "limit": 10,
  "totalPages": 1
}
```

---

### 8. Get Full Invoice Details (Business Recipient)

```http
GET /invoices/received/:receiptId/details?businessId=biz-123
```

**Description:** Fetch the full authoritative invoice document from the issuer's database (for business recipients).

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `receiptId` | string | Receipt ID (from list endpoint) |

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `businessId` | string | Yes | Your business ID (required for tenant context) |

**Success Response (200 OK):**

```json
{
  "id": "invoice-60d5ec49c1234567890abcd1",
  "issuerBusinessId": "biz-456",
  "invoiceNumber": "INV-2025-001",
  "status": "ISSUED",
  "totalAmount": 2000.0,
  "currency": "USD",
  "amountPaid": 0,
  "issuedDate": "2025-04-04T00:00:00Z",
  "dueDate": "2025-05-04T00:00:00Z",
  "description": "Services for March 2025",
  "paymentTerms": "NET 30",
  "recipient": {
    "type": "PLATFORM_BUSINESS",
    "platformId": "biz-123",
    "email": "billing@ourcompany.com",
    "resolutionStatus": "RESOLVED"
  },
  "lineItems": [
    {
      "id": "item-60d5ec49c1234567890abcd1",
      "productId": "prod-123",
      "productName": "Consulting Services",
      "quantity": 10,
      "unitPrice": 150.0,
      "amount": 1500.0,
      "description": "20 hours of consulting"
    },
    {
      "id": "item-60d5ec49c1234567890abcd2",
      "productId": "prod-456",
      "productName": "Software License",
      "quantity": 1,
      "unitPrice": 500.0,
      "amount": 500.0
    }
  ],
  "createdAt": "2025-04-04T10:30:00Z",
  "updatedAt": "2025-04-04T11:00:00Z"
}
```

**Error Responses:**

- **404 Not Found** - Receipt or invoice doesn't exist

  ```json
  {
    "statusCode": 404,
    "message": "Invoice not found",
    "error": "Not Found"
  }
  ```

- **403 Forbidden** - You don't have access to this invoice
  ```json
  {
    "statusCode": 403,
    "message": "You do not have access to this invoice",
    "error": "Forbidden"
  }
  ```

---

### 9. Get Full Invoice Details (Individual Recipient)

```http
GET /invoices/received/individual/:receiptId/details
```

**Description:** Fetch the full authoritative invoice document for individual recipients.

**Required Guards:** `JwtAuthGuard`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `receiptId` | string | Receipt ID (from list endpoint) |

**Success Response (200 OK):**
Same as endpoint 8 (full invoice details)

**Error Responses:**

- **404 Not Found** - Receipt or invoice doesn't exist
- **403 Forbidden** - You don't have access to this invoice

---

## BULK IMPORT ENDPOINTS

These endpoints allow importing multiple invoices from CSV or Excel files.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`, `BusinessRolesGuard`  
**Required Roles:** `OWNER`, `ADMIN`

---

### 10. Get Import Template

```http
GET /invoices/import/template?businessId=biz-123
```

**Description:** Retrieve a CSV/Excel template and example format for bulk importing invoices.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`, `BusinessRolesGuard`

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `businessId` | string | Yes | Your business ID (required for tenant context) |

**Success Response (200 OK):**

```json
{
  "csvExample": "invoiceNumber,recipientType,recipientEmail,recipientDisplayName,productIds,productNames,quantities,unitPrices,issuedDate,dueDate\nINV-2024-001,EXTERNAL,john@example.com,John Doe,PROD-001,Website Service,1,5000.00,2024-01-15,2024-02-15",
  "csvColumns": [
    "invoiceNumber",
    "recipientType",
    "recipientPlatformId",
    "recipientEmail",
    "recipientDisplayName",
    "productIds",
    "productNames",
    "quantities",
    "unitPrices",
    "issuedDate",
    "dueDate",
    "description",
    "paymentTerms",
    "currency"
  ],
  "recipientTypes": ["PLATFORM_BUSINESS", "PLATFORM_INDIVIDUAL", "EXTERNAL"],
  "notes": "Format: Use comma-separated values. Dates must be in YYYY-MM-DD format..."
}
```

---

### 11. Bulk Import Invoices from File

```http
POST /invoices/import
```

**Content-Type:** `multipart/form-data`

**Description:** Upload a CSV or XLSX file to create multiple invoices in bulk. Each row represents one invoice. Invoices are created in DRAFT status.

**Required Guards:** `JwtAuthGuard`, `TenantContextGuard`, `BusinessRolesGuard`

**Form Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `businessId` | string | Yes | Your business ID (should be sent in form data for tenant context) |
| `file` | file | Yes | CSV or XLSX file |

**CSV Columns:**

**Required:**
| Column | Type | Example | Description |
|--------|------|---------|-------------|
| `invoiceNumber` | string | `INV-2024-001` | Unique invoice identifier |
| `recipientType` | enum | `EXTERNAL` | Type of recipient: PLATFORM_BUSINESS, PLATFORM_INDIVIDUAL, or EXTERNAL |
| `issuedDate` | date | `2024-01-15` | Invoice issue date (YYYY-MM-DD format) |
| `dueDate` | date | `2024-02-15` | Payment due date (YYYY-MM-DD format) |

**Optional:**
| Column | Type | Example | Description |
|--------|------|---------|-------------|
| `recipientPlatformId` | string | `507f1f77bcf86cd799439011` | Business ID (required for PLATFORM_BUSINESS) or User ID |
| `recipientEmail` | string | `john@example.com` | Email address (required for PLATFORM_INDIVIDUAL and EXTERNAL) |
| `recipientDisplayName` | string | `John Doe` | Display name (required for EXTERNAL recipients) |
| `productIds` | string | `PROD-001,PROD-002` or `PROD-001\|PROD-002` | Delimited product IDs (pipe or comma) |
| `productNames` | string | `Service A,Service B` or `Service A\|Service B` | Delimited product names (pipe or comma) |
| `quantities` | string | `1,2` or `1\|2` | Delimited quantities (pipe or comma) |
| `unitPrices` | string | `5000.00,2500.00` or `5000.00\|2500.00` | Delimited unit prices (pipe or comma) |
| `lineItemsJson` | string | `[{...}]` | Or provide JSON array of line items for complex cases |
| `description` | string | `Monthly services` | Invoice description |
| `paymentTerms` | string | `NET30` | Payment terms |
| `currency` | string | `TND` | Currency code (default: TND) |

**Recipient Type Rules:**

- **PLATFORM_BUSINESS**: Requires `recipientPlatformId`
- **PLATFORM_INDIVIDUAL**: Requires `recipientEmail`
- **EXTERNAL**: Requires both `recipientEmail` AND `recipientDisplayName`

**Line Items Format:**

**Option 1 - Multi-item Line Items:**

```csv
invoiceNumber,recipientType,recipientEmail,recipientDisplayName,productIds,productNames,quantities,unitPrices,issuedDate,dueDate
INV-001,EXTERNAL,john@example.com,John Doe,PROD-001,Service,1,5000.00,2024-01-15,2024-02-15
INV-002,EXTERNAL,jane@example.com,Jane Smith,PROD-001|PROD-002,Service A|Service B,1|2,5000.00|2500.00,2024-01-15,2024-02-15
INV-003,EXTERNAL,bob@example.com,Bob Jones,PROD-001,PROD-002,Service A,Service B,1,2,5000.00,2500.00,2024-01-15,2024-02-15
```

For multiple line items in a single invoice row, you can use either:

- **Pipe delimiter** (`|`): `PROD-001|PROD-002` or
- **Comma delimiter** (`,`): `PROD-001,PROD-002`

The system automatically detects which delimiter is used.

**Option 2 - Complex (JSON array):**

```csv
invoiceNumber,recipientType,recipientEmail,recipientDisplayName,lineItemsJson,issuedDate,dueDate
INV-001,EXTERNAL,test@example.com,Test Inc,"[{\"productId\":\"PROD-001\",\"productName\":\"Service\",\"quantity\":1,\"unitPrice\":5000.00}]",2024-01-15,2024-02-15
```

**Success Response (200 OK):**

```json
{
  "totalRecords": 2,
  "successCount": 2,
  "failedCount": 0,
  "warningCount": 0,
  "results": [
    {
      "invoiceNumber": "INV-2024-001",
      "invoiceId": "507f1f77bcf86cd799439011",
      "status": "success",
      "message": "Invoice created successfully",
      "lineItemsCount": 2,
      "totalAmount": 7500.5
    },
    {
      "invoiceNumber": "INV-2024-002",
      "invoiceId": "507f1f77bcf86cd799439012",
      "status": "success",
      "message": "Invoice created successfully",
      "lineItemsCount": 1,
      "totalAmount": 2000.0
    }
  ],
  "importStartedAt": "2024-01-15T10:00:00.000Z",
  "importCompletedAt": "2024-01-15T10:00:05.000Z",
  "processingTimeMs": 5234
}
```

**Partial Failure Response (200 OK - with some failures):**

```json
{
  "totalRecords": 3,
  "successCount": 2,
  "failedCount": 1,
  "warningCount": 0,
  "results": [
    {
      "invoiceNumber": "INV-2024-001",
      "invoiceId": "507f1f77bcf86cd799439011",
      "status": "success",
      "message": "Invoice created successfully",
      "lineItemsCount": 2,
      "totalAmount": 7500.5
    },
    {
      "invoiceNumber": "INV-2024-002",
      "status": "error",
      "message": "Row 3: dueDate must be after or equal to issuedDate"
    }
  ],
  "importStartedAt": "2024-01-15T10:00:00.000Z",
  "importCompletedAt": "2024-01-15T10:00:05.000Z",
  "processingTimeMs": 5234
}
```

**Error Responses:**

- **400 Bad Request** - Invalid file format or structure
  ```json
  {
    "statusCode": 400,
    "message": "File import failed: Unsupported file format. Please upload a CSV or XLSX file.",
    "error": "Bad Request"
  }
  ```

**Validation Rules:**

- Dates must be in YYYY-MM-DD format or valid ISO date
- `dueDate` must be ≥ `issuedDate`
- Excel serial numbers are automatically converted
- Required fields vary by recipient type
- Line items must have matching array lengths
- All invoices created in DRAFT status

---

## Service Architecture (Internal)

### InvoiceIssuanceService

**Location:** `src/invoices/services/invoice-issuance.service.ts`

Handles _all operations for invoices issued by your business_:

- Create draft invoices
- List invoices issued by your business
- Fetch individual invoices
- Update draft invoices only (DRAFT status)
- Transition invoice state (DRAFT → ISSUED → PAID, etc.)
- Sync invoice changes to InvoiceReceipts in platform DB

**Key Properties:**

- Invoices stored in issuer's tenant database (authoritative)
- Only OWNER/ADMIN roles can manage issued invoices
- Email normalization (lowercase) for recipient matching
- State transitions validated against INVOICE_STATUS_TRANSITIONS rules

### InvoiceReceiptService

**Location:** `src/invoices/services/invoice-receipt.service.ts`

Handles _viewing invoices received by your business or personal account_:

- List invoices received by a business
- List invoices received by an individual user
- Fetch full invoice details from issuer's database
- Verify access permissions for cross-tenant invoice viewing

**Key Properties:**

- InvoiceReceipts stored in platform database (read-only from recipient perspective)
- Synced from issuer invoices for discoverability
- Any authenticated user can view their received invoices
- Cross-tenant queries use tenant connection routing

### RecipientResolutionService

**Location:** `src/invoices/services/recipient-resolution.service.ts`

Handles _background identity resolution for external recipients_:

- Detects when external recipients (email-only) claim platform identity
- Updates resolution status (PENDING → RESOLVED)
- Manages NEVER_RESOLVED status for recipients who never claim account

**Key Properties:**

- Background async operations (non-blocking invoice creation)
- Updates InvoiceRecipient.resolutionStatus and lastResolutionAttempt
- Works across issuer and platform databases

---

## Request/Response Models Reference

### CreateInvoiceRecipientDto

| Field         | Type                 | Required | Description                                                                                                                                 |
| ------------- | -------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`        | InvoiceRecipientType | Yes      | Type of recipient                                                                                                                           |
| `platformId`  | string               | No       | Business ID or User ID. Optional for platform recipients - if omitted, system auto-searches by email. Required for EXTERNAL → `displayName` |
| `email`       | string               | Yes      | Email address. Used for magic search when `platformId` not provided for platform recipients                                                 |
| `displayName` | string               | No       | Display name (required for EXTERNAL recipients)                                                                                             |

**Magic Search Behavior:**

- **PLATFORM_BUSINESS + email only**: Searches Business collection for matching email, auto-populates `platformId`
- **PLATFORM_INDIVIDUAL + email only**: Searches User collection for matching email, auto-populates `platformId`
- **PLATFORM\_\* + platformId provided**: Uses provided ID, no search performed
- **EXTERNAL + email + displayName**: No search, email-only recipient accepted

### CreateInvoiceLineItemDto

| Field         | Type   | Required | Description      |
| ------------- | ------ | -------- | ---------------- |
| `productId`   | string | Yes      | Product ID       |
| `productName` | string | Yes      | Product name     |
| `quantity`    | number | Yes      | Quantity (≥ 0)   |
| `unitPrice`   | number | Yes      | Unit price (≥ 0) |
| `description` | string | No       | Item description |

### InvoiceRecipientResponseDto

| Field                   | Type                      | Description                       |
| ----------------------- | ------------------------- | --------------------------------- |
| `type`                  | InvoiceRecipientType      | Type of recipient                 |
| `platformId`            | string                    | Business ID or User ID            |
| `tenantDatabaseName`    | string                    | Tenant DB (if platform recipient) |
| `email`                 | string                    | Email address                     |
| `displayName`           | string                    | Display name                      |
| `resolutionStatus`      | RecipientResolutionStatus | Identity resolution status        |
| `lastResolutionAttempt` | Date                      | Last resolution attempt timestamp |

### InvoiceLineItemResponseDto

| Field         | Type   | Description                         |
| ------------- | ------ | ----------------------------------- |
| `id`          | string | Line item ID                        |
| `productId`   | string | Product ID                          |
| `productName` | string | Product name                        |
| `quantity`    | number | Quantity                            |
| `unitPrice`   | number | Unit price                          |
| `amount`      | number | Total amount (quantity × unitPrice) |
| `description` | string | Item description                    |

---

## Common HTTP Status Codes

| Code | Meaning                                |
| ---- | -------------------------------------- |
| 200  | Success (GET, PATCH)                   |
| 201  | Created (POST)                         |
| 400  | Bad Request (invalid input, duplicate) |
| 401  | Unauthorized (missing/invalid token)   |
| 403  | Forbidden (insufficient permissions)   |
| 404  | Not Found (resource doesn't exist)     |
| 500  | Internal Server Error                  |

---

## Valid State Transitions

```
DRAFT   → ISSUED, VOIDED, ARCHIVED
ISSUED  → VIEWED, VOIDED, PARTIAL, PAID, DISPUTED
VIEWED  → PAID, PARTIAL, VOIDED, DISPUTED, OVERDUE
PARTIAL → PAID, VOIDED, DISPUTED, OVERDUE
PAID    → ARCHIVED
OVERDUE → PAID, DISPUTED, VOIDED
DISPUTED → PAID, VOIDED, OVERDUE
VOIDED  → ARCHIVED
ARCHIVED → (terminal state, no transitions)
```

---

## Examples

### Example 1: Create Invoice with Magic Search (PLATFORM_BUSINESS)

Create invoice using just email - system auto-finds the business:

```bash
curl -X POST http://localhost:3000/invoices \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "businessId": "biz-123",
    "invoiceNumber": "INV-2025-001",
    "issuedDate": "2025-04-04T00:00:00Z",
    "dueDate": "2025-05-04T00:00:00Z",
    "currency": "USD",
    "recipient": {
      "type": "PLATFORM_BUSINESS",
      "email": "billing@targetcompany.com"
    },
    "lineItems": [
      {
        "productId": "prod-123",
        "productName": "Consulting Services",
        "quantity": 10,
        "unitPrice": 150.00
      }
    ]
  }'
```

**Response:** `platformId` is auto-populated from the business found by email search

**Error if recipient not found:**

```json
{
  "statusCode": 400,
  "message": "Cannot find PLATFORM_BUSINESS recipient with email billing@targetcompany.com. Please provide platformId or create the invoice as type EXTERNAL.",
  "error": "Bad Request"
}
```

### Example 2: Create Invoice with PLATFORM_INDIVIDUAL (User Email)

Create invoice for registered platform user by just email:

```bash
curl -X POST http://localhost:3000/invoices \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "businessId": "biz-123",
    "invoiceNumber": "INV-2025-002",
    "issuedDate": "2025-04-04T00:00:00Z",
    "dueDate": "2025-05-04T00:00:00Z",
    "currency": "USD",
    "recipient": {
      "type": "PLATFORM_INDIVIDUAL",
      "email": "john.doe@example.com"
    },
    "lineItems": [
      {
        "productId": "prod-123",
        "productName": "Consulting",
        "quantity": 5,
        "unitPrice": 200.00
      }
    ]
  }'
```

**Response:** `platformId` is auto-populated with the user ID found by email search

### Example 3: Create Invoice with Explicit platformId (No Search)

Create invoice with explicit business ID - no magic search performed:

```bash
curl -X POST http://localhost:3000/invoices \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "businessId": "biz-123",
    "invoiceNumber": "INV-2025-003",
    "issuedDate": "2025-04-04T00:00:00Z",
    "dueDate": "2025-05-04T00:00:00Z",
    "currency": "USD",
    "recipient": {
      "type": "PLATFORM_BUSINESS",
      "platformId": "biz-456",
      "email": "billing@knowncustomer.com"
    },
    "lineItems": [
      {
        "productId": "prod-1",
        "productName": "Service",
        "quantity": 1,
        "unitPrice": 1000
      }
    ]
  }'
```

### Example 4: Create Invoice for EXTERNAL Recipient (No Search)

Create invoice for external contact (no platform account):

```bash
curl -X POST http://localhost:3000/invoices \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "businessId": "biz-123",
    "invoiceNumber": "INV-2025-004",
    "issuedDate": "2025-04-04T00:00:00Z",
    "dueDate": "2025-05-04T00:00:00Z",
    "currency": "USD",
    "recipient": {
      "type": "EXTERNAL",
      "email": "external@unknowncompany.com",
      "displayName": "External Company Ltd"
    },
    "lineItems": [
      {
        "productId": "prod-1",
        "productName": "Service",
        "quantity": 1,
        "unitPrice": 1000
      }
    ]
  }'
```

**No magic search performed for EXTERNAL recipients - accepted as email-only**

### Example 5: Create and Issue an Invoice

```bash
# 1. Create invoice in DRAFT using magic search
curl -X POST http://localhost:3000/invoices \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "businessId": "biz-123",
    "invoiceNumber": "INV-2025-005",
    "issuedDate": "2025-04-04T00:00:00Z",
    "dueDate": "2025-05-04T00:00:00Z",
    "currency": "USD",
    "recipient": {
      "type": "PLATFORM_BUSINESS",
      "email": "billing@customer.com"
    },
    "lineItems": [
      {
        "productId": "prod-1",
        "productName": "Service",
        "quantity": 1,
        "unitPrice": 1000
      }
    ]
  }'

# 2. Transition to ISSUED
curl -X POST http://localhost:3000/invoices/INVOICE_ID/transition \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "businessId": "biz-123",
    "newStatus": "ISSUED",
    "reason": "Publishing to customer"
  }'
```

### Example 6: Record Payment

```bash
curl -X POST http://localhost:3000/invoices/INVOICE_ID/transition \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "businessId": "biz-123",
    "newStatus": "PAID",
    "amountPaid": 1000,
    "reason": "Payment received - Check #12345"
  }'
```

### Example 7: Retrieve Received Invoices

```bash
# For business recipients
curl -X GET "http://localhost:3000/invoices/received/business?businessId=biz-123&status=ISSUED&page=1&limit=20" \
  -H "Authorization: Bearer YOUR_TOKEN"

# For individual recipients
curl -X GET "http://localhost:3000/invoices/received/individual?status=ISSUED&page=1&limit=20" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Migration Guide: Magic Search Feature

### What Changed?

The invoice creation endpoint now supports **automatic recipient lookup** via email. This reduces the need for frontend applications to perform separate business/user lookups before creating invoices.

### For Frontend Developers

**Before (Manual Lookup Required):**

```javascript
// Step 1: Search for business by email
const business = await api.searchBusiness({ email: 'billing@company.com' });

// Step 2: Create invoice with business ID
const invoice = await api.createInvoice({
  businessId: 'biz-123',
  recipient: {
    type: 'PLATFORM_BUSINESS',
    platformId: business.id,
    email: 'billing@company.com'
  },
  lineItems: [...]
});
```

**After (Magic Search Handles It):**

```javascript
// Just send email - backend auto-resolves the ID
const invoice = await api.createInvoice({
  businessId: 'biz-123',
  recipient: {
    type: 'PLATFORM_BUSINESS',
    email: 'billing@company.com'
    // NO platformId needed - auto-resolved by backend!
  },
  lineItems: [...]
});
```

### When Does Magic Search Apply?

| Recipient Type      | Has platformId | Has email | Behavior                                      |
| ------------------- | -------------- | --------- | --------------------------------------------- |
| PLATFORM_BUSINESS   | ✓ Yes          | Yes/No    | Uses provided platformId, no search           |
| PLATFORM_BUSINESS   | ✗ No           | ✓ Yes     | **Searches Business by email, auto-resolves** |
| PLATFORM_INDIVIDUAL | ✓ Yes          | Yes/No    | Uses provided platformId, no search           |
| PLATFORM_INDIVIDUAL | ✗ No           | ✓ Yes     | **Searches User by email, auto-resolves**     |
| EXTERNAL            | Any            | ✓ Yes     | No search, email-only accepted                |

### Error Handling

If magic search fails (recipient not found), the API returns a helpful error:

```json
{
  "statusCode": 400,
  "message": "Cannot find PLATFORM_BUSINESS recipient with email billing@unknown.com. Please provide platformId or create the invoice as type EXTERNAL.",
  "error": "Bad Request"
}
```

**Solutions:**

1. Verify the email is correct
2. Provide explicit `platformId` if known
3. Use `EXTERNAL` type if recipient is not on platform
4. Create the recipient on platform first, then retry
