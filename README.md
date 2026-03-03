# Accountia API Reference

Complete API reference for Accountia API endpoints with all possible requests and responses based on actual controller implementation.

## Base URL

```
http://localhost:3000/api
```

## Authentication Headers

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

---

## 🔐 Authentication Endpoints

### GET /auth/google

Start Google OAuth login/signup flow.

**Query Parameters:**

- `mode` (optional): 'login' | 'register' (default: 'login')
- `lang` (optional): Language (default: 'en')
- `redirectUri` (optional): Custom redirect URI

**Responses:**

**302 Found**
Redirects to Google OAuth consent screen.

---

### GET /auth/google/callback

Handle Google OAuth callback and redirect to frontend.

**Query Parameters:**

- `code` (optional): OAuth authorization code
- `state` (optional): OAuth state parameter

**Responses:**

**302 Found**
Redirects to frontend callback route with success/error parameters.

---

### POST /auth/register

Register a new user.

**Request Body:**

```json
{
  "username": "john_doe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "birthdate": "2000-01-01",
  "phoneNumber": "+1234567890",
  "acceptTerms": true
}
```

**Responses:**

**201 Created**

```json
{
  "message": "Registration successful! Please check your email to confirm your account.",
  "email": "john.doe@example.com"
}
```

**409 Conflict**

```json
{
  "message": "User already exists"
}
```

---

### POST /auth/login

Login user.

**Request Body:**

```json
{
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

**Responses:**

**200 OK (Login Successful)**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "accessTokenExpiresAt": "2024-02-19T14:07:00.000Z",
  "refreshTokenExpiresAt": "2024-02-26T14:07:00.000Z",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+1234567890",
    "role": "CLIENT"
  }
}
```

**200 OK (2FA Required)**

```json
{
  "tempToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "twoFactorRequired": true
}
```

**401 Unauthorized**

```json
{
  "message": "Invalid credentials"
}
```

**403 Forbidden**

```json
{
  "message": "Account locked or deactivated"
}
```

---

### POST /auth/2fa/setup

Setup 2FA (generate secret, QR).

**Headers:**

```http
Authorization: Bearer <access_token>
```

**Responses:**

**200 OK**

```json
{
  "qrCode": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "secret": "JBSWY3DPEHPK3PXP"
}
```

---

### POST /auth/2fa/verify

Verify and enable 2FA.

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "code": "123456"
}
```

**Responses:**

**200 OK**

```json
{
  "enabled": true
}
```

---

### POST /auth/2fa/login

2FA login step (validate temp token + TOTP).

**Request Body:**

```json
{
  "tempToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "code": "123456"
}
```

**Responses:**

**200 OK**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "accessTokenExpiresAt": "2024-02-19T14:07:00.000Z",
  "refreshTokenExpiresAt": "2024-02-26T14:07:00.000Z",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+1234567890",
    "role": "CLIENT"
  }
}
```

---

### POST /auth/logout

Logout user.

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Responses:**

**200 OK**
Logout successful (no content).

**401 Unauthorized**
Invalid or expired access token.

---

### POST /auth/refresh

Refresh authentication tokens.

**Headers:**

```http
Authorization: Bearer <refresh_token>
```

**Responses:**

**200 OK**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "accessTokenExpiresAt": "2024-02-19T14:07:00.000Z",
  "refreshTokenExpiresAt": "2024-02-26T14:07:00.000Z",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+1234567890",
    "role": "CLIENT"
  }
}
```

**401 Unauthorized**
Invalid or expired refresh token.

---

### POST /auth/forgot-password

Request password reset.

**Request Body:**

```json
{
  "email": "john.doe@example.com"
}
```

**Responses:**

**200 OK**
Password reset email sent (no content).

---

### POST /auth/reset-password

Reset password.

**Request Body:**

```json
{
  "token": "reset_token_here",
  "newPassword": "NewPassword123!"
}
```

**Responses:**

**200 OK**
Password reset successful (no content).

**400 Bad Request**
Invalid or expired token.

---

### GET /auth/confirm-email/:token

Confirm email address.

**URL Parameters:**

- `token` (string): Email confirmation token

**Responses:**

**200 OK (HTML)**
Returns HTML confirmation page with success/error message.

**400 Bad Request**
Invalid or expired token (returns JSON or HTML).

---

### GET /auth/fetchuser

Fetch current user profile.

**Headers:**

```http
Authorization: Bearer <access_token>
```

**Responses:**

**200 OK**

```json
{
  "id": "615f2e0a6c6d5c0e1a1e4a01",
  "username": "john_doe",
  "email": "john.doe@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "birthdate": "2000-01-01",
  "dateJoined": "2023-10-22T14:48:00Z",
  "profilePicture": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "emailConfirmed": true,
  "phoneNumber": "+1234567890",
  "role": "CLIENT"
}
```

**401 Unauthorized**
Invalid access token.

**404 Not Found**
User not found.

---

### POST /auth/fetchuserbyid

Fetch user by ID.

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "userId": "615f2e0a6c6d5c0e1a1e4a01"
}
```

**Responses:**

**200 OK**

```json
{
  "id": "615f2e0a6c6d5c0e1a1e4a01",
  "username": "john_doe",
  "firstName": "John",
  "lastName": "Doe",
  "birthdate": "2000-01-01",
  "dateJoined": "2023-10-22T14:48:00Z",
  "profilePicture": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "phoneNumber": "+1234567890",
  "role": "CLIENT"
}
```

**400 Bad Request**
Invalid user ID format.

**401 Unauthorized**
Invalid access token.

**404 Not Found**
User not found.

---

### PUT /auth/update

Update user profile (full update).

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "username": "john_doe_updated",
  "firstName": "John Updated",
  "lastName": "Doe Updated",
  "phoneNumber": "+1234567890",
  "profilePicture": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
}
```

**Responses:**

**200 OK**

```json
{
  "id": "615f2e0a6c6d5c0e1a1e4a01",
  "username": "john_doe_updated",
  "email": "john.doe@example.com",
  "firstName": "John Updated",
  "lastName": "Doe Updated",
  "birthdate": "2000-01-01",
  "dateJoined": "2023-10-22T14:48:00Z",
  "profilePicture": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "emailConfirmed": true,
  "phoneNumber": "+1234567890",
  "role": "CLIENT"
}
```

**400 Bad Request**
Invalid update data.

**401 Unauthorized**
Invalid access token.

**404 Not Found**
User not found.

**409 Conflict**
Username or email already taken.

---

### PATCH /auth/update

Update user profile (partial update).

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "firstName": "John Updated"
}
```

**Responses:**

**200 OK**
Same as PUT /auth/update response.

**400 Bad Request**
Invalid update data.

**401 Unauthorized**
Invalid access token.

**404 Not Found**
User not found.

**409 Conflict**
Username or email already taken.

---

### DELETE /auth/delete

Delete your own user account.

**Headers:**

```http
Authorization: Bearer <access_token>
```

**Responses:**

**200 OK**

```json
{
  "message": "Account deleted successfully"
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Cannot delete admin accounts.

**500 Internal Server Error**
Failed to delete account.

---

### DELETE /auth/users/:id

Admin: delete a user by id.

**Headers:**

```http
Authorization: Bearer <access_token>
```

**Required Roles:** Admin (AdminGuard)

**URL Parameters:**

- `id` (string): User ID to delete

**Responses:**

**200 OK**

```json
{
  "message": "User removed successfully"
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient privileges.

**404 Not Found**
User not found.

**400 Bad Request**
Administrators cannot delete themselves.

---

### GET /auth/users

Admin: fetch all users.

**Headers:**

```http
Authorization: Bearer <access_token>
```

**Required Roles:** Admin (AdminGuard)

**Responses:**

**200 OK**

```json
{
  "users": [
    {
      "id": "615f2e0a6c6d5c0e1a1e4a01",
      "username": "john_doe",
      "firstName": "John",
      "lastName": "Doe",
      "birthdate": "2000-01-01",
      "dateJoined": "2023-10-22T14:48:00Z",
      "profilePicture": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
      "phoneNumber": "+1234567890",
      "role": "CLIENT"
    }
  ]
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient privileges.

---

### POST /auth/resend-confirmation-email

Resend confirmation email.

**Request Body:**

```json
{
  "email": "john.doe@example.com"
}
```

**Responses:**

**200 OK**

```json
{
  "message": "Confirmation email sent successfully"
}
```

**404 Not Found**
User not found.

**409 Conflict**
Email already confirmed.

**429 Too Many Requests**
Too many requests.

---

### PATCH /auth/change-role

Change user role (Platform Owner/Admin only).

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Required Roles:** `PLATFORM_OWNER`, `PLATFORM_ADMIN`

**Request Body:**

```json
{
  "userId": "615f2e0a6c6d5c0e1a1e4a01",
  "newRole": "BUSINESS_OWNER"
}
```

**Responses:**

**200 OK**

```json
{
  "message": "User role changed successfully",
  "userId": "615f2e0a6c6d5c0e1a1e4a01",
  "newRole": "BUSINESS_OWNER",
  "previousRole": "CLIENT"
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

**404 Not Found**
User not found.

---

## 🏢 Business Management Endpoints

### POST /business/apply

Submit a business application.

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "businessName": "Tech Solutions Inc.",
  "description": "A technology company specializing in software development",
  "website": "https://techsolutions.com",
  "phone": "+1-555-0123"
}
```

**Responses:**

**201 Created**

```json
{
  "id": "507f1f77bcf86cd799439011",
  "businessName": "Tech Solutions Inc.",
  "description": "A technology company specializing in software development",
  "website": "https://techsolutions.com",
  "phone": "+1-555-0123",
  "applicantId": "615f2e0a6c6d5c0e1a1e4a01",
  "status": "pending",
  "createdAt": "2024-02-17T16:30:00.000Z"
}
```

**400 Bad Request**
Invalid request data.

**401 Unauthorized**
Invalid access token.

---

### GET /business/applications

Get all business applications (Platform Admin only).

**Headers:**

```http
Authorization: Bearer <access_token>
```

**Required Roles:** `PLATFORM_OWNER`, `PLATFORM_ADMIN`

**Responses:**

**200 OK**

```json
{
  "applications": [
    {
      "id": "507f1f77bcf86cd799439011",
      "businessName": "Tech Solutions Inc.",
      "description": "A technology company specializing in software development",
      "website": "https://techsolutions.com",
      "phone": "+1-555-0123",
      "applicantId": "615f2e0a6c6d5c0e1a1e4a01",
      "status": "pending",
      "createdAt": "2024-02-17T16:30:00.000Z"
    }
  ]
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

---

### POST /business/applications/:id/review

Review business application (Platform Admin only).

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Required Roles:** `PLATFORM_OWNER`, `PLATFORM_ADMIN`

**URL Parameters:**

- `id` (string): Application ID

**Request Body:**

```json
{
  "status": "approved",
  "reviewNotes": "Application approved - business meets all requirements"
}
```

**Responses:**

**200 OK**

```json
{
  "id": "507f1f77bcf86cd799439011",
  "businessName": "Tech Solutions Inc.",
  "status": "approved",
  "reviewedBy": "507f1f77bcf86cd799439012",
  "reviewNotes": "Application approved - business meets all requirements",
  "businessId": "507f1f77bcf86cd799439013",
  "updatedAt": "2024-02-17T16:30:00.000Z"
}
```

**400 Bad Request**
Invalid request data.

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

**404 Not Found**
Application not found.

---

### GET /business/my

Get my businesses.

**Headers:**

```http
Authorization: Bearer <access_token>
```

**Responses:**

**200 OK**

```json
{
  "businesses": [
    {
      "id": "507f1f77bcf86cd799439011",
      "name": "Tech Solutions Inc.",
      "phone": "+1-555-0123",
      "status": "approved",
      "isActive": true,
      "createdAt": "2024-02-17T16:30:00.000Z"
    }
  ]
}
```

**401 Unauthorized**
Invalid access token.

---

### GET /business/all

Get all businesses (Platform Admin only).

**Headers:**

```http
Authorization: Bearer <access_token>
```

**Required Roles:** `PLATFORM_OWNER`, `PLATFORM_ADMIN`

**Responses:**

**200 OK**

```json
{
  "businesses": [
    {
      "id": "507f1f77bcf86cd799439011",
      "name": "Tech Solutions Inc.",
      "phone": "+1-555-0123",
      "status": "approved",
      "isActive": true,
      "createdAt": "2024-02-17T16:30:00.000Z"
    }
  ]
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

---

### GET /business/:id

Get business by ID.

**Headers:**

```http
Authorization: Bearer <access_token>
```

**URL Parameters:**

- `id` (string): Business ID

**Responses:**

**200 OK**

```json
{
  "id": "507f1f77bcf86cd799439011",
  "name": "Tech Solutions Inc.",
  "description": "A technology company specializing in software development",
  "website": "https://techsolutions.com",
  "phone": "+1-555-0123",
  "databaseName": "tech_solutions_inc_1708198200000",
  "status": "approved",
  "isActive": true,
  "tags": ["technology", "software"],
  "createdAt": "2024-02-17T16:30:00.000Z",
  "updatedAt": "2024-02-17T16:30:00.000Z"
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

**404 Not Found**
Business not found.

---

### PUT /business/:id

Update business.

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**URL Parameters:**

- `id` (string): Business ID

**Request Body:**

```json
{
  "name": "Updated Business Name",
  "description": "Updated description",
  "website": "https://updated-website.com",
  "tags": ["technology", "software", "innovation"]
}
```

**Responses:**

**200 OK**

```json
{
  "id": "507f1f77bcf86cd799439011",
  "name": "Updated Business Name",
  "description": "Updated description",
  "website": "https://updated-website.com",
  "phone": "+1-555-0123",
  "databaseName": "tech_solutions_inc_1708198200000",
  "status": "approved",
  "isActive": true,
  "tags": ["technology", "software", "innovation"],
  "createdAt": "2024-02-17T16:30:00.000Z",
  "updatedAt": "2024-02-18T10:15:00.000Z"
}
```

**400 Bad Request**
Invalid request data.

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

**404 Not Found**
Business not found.

---

### DELETE /business/:id

Delete business.

**Headers:**

```http
Authorization: Bearer <access_token>
```

**URL Parameters:**

- `id` (string): Business ID

**Responses:**

**200 OK**

```json
{
  "message": "Business deleted successfully"
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

**404 Not Found**
Business not found.

---

### POST /business/:id/users

Assign user to business.

**Headers:**

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**URL Parameters:**

- `id` (string): Business ID

**Request Body:**

```json
{
  "userId": "507f1f77bcf86cd799439012",
  "role": "admin"
}
```

**Responses:**

**201 Created**

```json
{
  "id": "507f1f77bcf86cd799439013",
  "businessId": "507f1f77bcf86cd799439011",
  "userId": "507f1f77bcf86cd799439012",
  "role": "admin",
  "assignedBy": "615f2e0a6c6d5c0e1a1e4a01",
  "isActive": true,
  "createdAt": "2024-02-17T16:30:00.000Z"
}
```

**400 Bad Request**
Invalid request data.

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

**404 Not Found**
Business not found.

---

### DELETE /business/:id/users/:userId

Unassign user from business.

**Headers:**

```http
Authorization: Bearer <access_token>
```

**URL Parameters:**

- `id` (string): Business ID
- `userId` (string): User ID to unassign

**Responses:**

**200 OK**

```json
{
  "message": "User unassigned from business successfully"
}
```

**401 Unauthorized**
Invalid access token.

**403 Forbidden**
Insufficient permissions.

**404 Not Found**
Business or user assignment not found.

---

## 🏥 Health Check

### GET /health

Check application health.

**Responses:**

**200 OK**

```json
{
  "status": "ok",
  "timestamp": "2024-02-17T16:30:00.000Z",
  "uptime": 3600,
  "version": "1.0.0"
}
```

---

## 📊 Error Response Format

All error responses follow this format:

```json
{
  "statusCode": 400,
  "message": "Error description",
  "timestamp": "2024-02-17T16:30:00.000Z",
  "errors": {
    "field": "validation error message"
  }
}
```

### Common HTTP Status Codes

- **200 OK**: Request successful
- **201 Created**: Resource created successfully
- **302 Found**: Redirect (OAuth flows)
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Authentication required or failed
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

---

## 🔐 Role Permissions

| Role           | Can Submit Application | Can View Own Businesses | Can View All Businesses | Can Review Applications | Can Manage Users  | Can Delete Users |
| -------------- | ---------------------- | ----------------------- | ----------------------- | ----------------------- | ----------------- | ---------------- |
| CLIENT         | ✅                     | ✅                      | ❌                      | ❌                      | ❌                | ❌               |
| BUSINESS_ADMIN | ❌                     | ✅                      | ❌                      | ❌                      | ❌                | ❌               |
| BUSINESS_OWNER | ✅                     | ✅                      | ❌                      | ❌                      | ✅ (own business) | ❌               |
| PLATFORM_ADMIN | ❌                     | ✅                      | ✅                      | ✅                      | ✅                | ✅               |
| PLATFORM_OWNER | ✅                     | ✅                      | ✅                      | ✅                      | ✅                | ✅               |

---

## 📝 Request Headers

### Required Headers for Authenticated Requests

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

### Optional Headers

```http
Accept: application/json
X-Request-ID: unique-request-id
```

---

## 🚀 Quick Start Examples

### 1. Register and Login

```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john.doe@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe",
    "birthdate": "2000-01-01",
    "acceptTerms": true
  }'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecurePass123!"
  }'
```

### 2. Submit Business Application

```bash
curl -X POST http://localhost:3000/api/business/apply \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "businessName": "Tech Solutions Inc.",
    "description": "A technology company specializing in software development",
    "website": "https://techsolutions.com",
    "phone": "+1-555-0123"
  }'
```

### 3. Get My Businesses

```bash
curl -X GET http://localhost:3000/api/business/my \
  -H "Authorization: Bearer <access_token>"
```

### 4. Google OAuth Login

```bash
# Start OAuth flow
curl -L http://localhost:3000/api/auth/google?mode=login

# After redirect, callback will handle token exchange
```

---

## 📞 Support

For support and questions, please create an issue in repository or contact the development team.

---

**Built with ❤️ using NestJS**
