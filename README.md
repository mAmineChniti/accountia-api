# Accountia API Documentation

This is comprehensive API documentation for Accountia API. The API is a RESTful API that allows you to interact with Accountia server for user authentication, profile management, and email verification.

## Base URL

```text
http://localhost:3000/api
```

## Environment Configuration

Required environment variables:

```bash
# Database
MONGO_URI=mongodb://localhost:27017/accountia

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=168h # 7 days

# Email Configuration (Gmail SMTP)
GMAIL_USERNAME=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587

# Frontend Configuration
FRONTEND_URL=https://yourdomain.com

# Server Configuration
APP_HOSTNAME=localhost
PORT=3000
```

## API Documentation UI

- The interactive Swagger UI is exposed at `/docs` route under the API base path
- Visit `http://localhost:3000/api/docs` to view API documentation and test endpoints

## Global Configuration

### Global Prefix

- All routes are prefixed with `/api`

### Global Validation Pipe

```typescript
{
  whitelist: true,           // Only allow defined properties
  forbidNonWhitelisted: true, // Reject unknown properties
  forbidUnknownValues: true,  // Strict validation
  transform: true            // Auto-transform types
}
```

### Global Exception Filter

- `ConflictExceptionFilter` handles structured conflict responses
- Preserves `type` field in conflict exceptions for frontend handling

### CORS Configuration

- Origin: `process.env.FRONTEND_URL`
- Credentials: enabled

### Swagger Configuration

- Available in non-production environments
- Bearer token authentication
- Title: "Accountia API"
- Version: "1.0"

## Authentication & Authorization

### JWT Strategy

- **Access Token**: 24 hours expiration
- **Refresh Token**: 7 days expiration
- Token format: Bearer token in Authorization header

### Guards

- `JwtAuthGuard`: Protects authenticated routes
- `RefreshJwtGuard`: Protects refresh token routes

### User Payload Structure

```typescript
interface UserPayload {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  phoneNumber?: string;
}
```

## Endpoints

### Authentication Module

#### POST `/auth/register` - Register a new user

**Basic Information**

- **HTTP Method**: POST
- **Route**: `/api/auth/register`
- **Module**: Auth
- **Controller**: AuthController
- **Method**: `register`

**Authentication & Authorization**

- **Authentication Required**: No
- **Guard**: None (public endpoint)
- **Roles/Permissions**: None

**Request Details**

**Request Body (RegisterDto)**

```typescript
interface RegisterDto {
  username: string; // Required, 5-20 chars
  email: string; // Required, valid email
  password: string; // Required, min 6 chars
  firstName: string; // Required, 2-50 chars
  lastName: string; // Required, 2-50 chars
  birthdate: string; // Required, ISO date string
  phoneNumber?: string; // Optional, string
  acceptTerms: boolean; // Required, must be true
  profilePicture?: string; // Optional, base64, max 7MB
}
```

**Validation Rules**

- `username`: `@IsNotEmpty()`, `@IsString()`, `@MinLength(5)`, `@MaxLength(20)`
- `email`: `@IsNotEmpty()`, `@IsEmail()`
- `password`: `@IsNotEmpty()`, `@IsString()`, `@MinLength(6)`
- `firstName`: `@IsNotEmpty()`, `@IsString()`, `@MinLength(2)`, `@MaxLength(50)`
- `lastName`: `@IsNotEmpty()`, `@IsString()`, `@MinLength(2)`, `@MaxLength(50)`
- `birthdate`: `@IsNotEmpty()`, `@IsDateString()`
- `acceptTerms`: `@IsNotEmpty()`, `@IsBoolean()`
- `profilePicture`: `@IsOptional()`, `@IsString()`, `@MaxLength(9333334)`

**Example Request Body**

```json
{
  "username": "john_doe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "birthdate": "2000-01-01",
  "phoneNumber": "+1234567890",
  "acceptTerms": true,
  "profilePicture": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
}
```

**Response Documentation**

**Success Response (201 Created)**

- **Type**: `RegistrationResponseDto`
- **Description**: User successfully registered, confirmation email sent

```json
{
  "message": "Registration successful! Please check your email to confirm your account.",
  "email": "john.doe@example.com"
}
```

**Error Responses**

**Validation Error (400 Bad Request)**

- **When**: Request body fails validation

```json
{
  "message": "Validation failed",
  "errors": {
    "username": "username must be at least 5 characters",
    "email": "invalid email format",
    "password": "password must contain at least one uppercase, lowercase, number, or special character",
    "acceptTerms": "You must accept the terms and conditions"
  }
}
```

**Conflict Error (409 Conflict)**

- **When**: User already exists

_Unconfirmed User Exists:_

```json
{
  "type": "EMAIL_NOT_CONFIRMED",
  "message": "Account exists but email is not confirmed. Please check your email or request a new confirmation.",
  "email": "john.doe@example.com",
  "userId": "507f1f77bcf86cd799439011"
}
```

_Confirmed User Exists:_

```json
{
  "type": "ACCOUNT_EXISTS",
  "message": "Username or email is already registered"
}
```

**Database & Business Logic Insights**

- **Tables Involved**: `users` collection
- **Relations**: None (single collection operation)
- **Transactions**: Single document save
- **Side Effects**:
  - Password hashed with bcrypt (salt rounds: 10)
  - Email confirmation token generated (32 hex chars)
  - Confirmation email sent via EmailService
- **Events Triggered**: None
- **Queue Jobs**: None
- **Caching**: None

**Frontend Integration Notes**

```typescript
// Common mistakes to avoid:
// 1. Not checking for EMAIL_NOT_CONFIRMED type
// 2. Not handling structured conflict responses
// 3. Not showing resend confirmation button for unconfirmed users

async function register(userData: RegisterDto) {
  const response = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userData),
  });

  const data = await response.json();

  if (response.ok) {
    // Show success message, prompt email check
    return { success: true, data };
  } else if (response.status === 409) {
    if (data.type === 'EMAIL_NOT_CONFIRMED') {
      // Show "Resend Confirmation Email" button
      return {
        success: false,
        type: 'EMAIL_NOT_CONFIRMED',
        email: data.email,
        userId: data.userId,
      };
    } else if (data.type === 'ACCOUNT_EXISTS') {
      // Show "Account exists" error
      return { success: false, type: 'ACCOUNT_EXISTS', message: data.message };
    }
  } else {
    // Show validation errors
    return { success: false, type: 'VALIDATION_ERROR', errors: data.errors };
  }
}
```

#### POST `/auth/login` - Login a user

**Basic Information**

- **HTTP Method**: POST
- **Route**: `/api/auth/login`
- **Module**: Auth
- **Controller**: AuthController
- **Method**: `login`

**Authentication & Authorization**

- **Authentication Required**: No
- **Guard**: None (public endpoint)
- **Roles/Permissions**: None

**Request Details**

**Request Body (LoginDto)**

```typescript
interface LoginDto {
  email: string; // Required, valid email
  password: string; // Required, string
}
```

**Validation Rules**

- `email`: `@IsNotEmpty()`, `@IsEmail()`
- `password`: `@IsNotEmpty()`, `@IsString()`

**Example Request Body**

```json
{
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

**Response Documentation**

**Success Response (200 OK)**

- **Type**: `AuthResponseDto`
- **Description**: Login successful, tokens returned

```json
{
  "accessToken": "<access_token>",
  "refreshToken": "<refresh_token>",
  "accessTokenExpiresAt": "2024-02-19T14:07:00.000Z",
  "refreshTokenExpiresAt": "2024-02-26T14:07:00.000Z",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+1234567890"
  }
}
```

**Error Responses**

**Validation Error (400 Bad Request)**

- **When**: Request body fails validation

```json
{
  "message": "Validation failed",
  "errors": {
    "email": "email is required",
    "password": "password must contain at least one uppercase, lowercase, number, or special character"
  }
}
```

**Unauthorized Error (401 Unauthorized)**

- **When**: Invalid credentials

```json
{
  "statusCode": 401,
  "message": "Invalid email or password",
  "timestamp": "2024-02-17T16:30:00.000Z"
}
```

**Forbidden Error (403 Forbidden)**

- **When**: Account locked

```json
{
  "statusCode": 403,
  "message": "Account is temporarily locked due to too many failed attempts",
  "timestamp": "2024-02-17T16:30:00.000Z"
}
```

- **When**: Account deactivated

```json
{
  "statusCode": 403,
  "message": "Account is deactivated",
  "timestamp": "2024-02-17T16:30:00.000Z"
}
```

- **When**: Email not confirmed

```json
{
  "statusCode": 403,
  "message": "Email not confirmed. Please confirm your email before logging in.",
  "timestamp": "2024-02-17T16:30:00.000Z"
}
```

**Too Many Requests (429 Too Many Requests)**

- **When**: Rate limit exceeded

```json
{
  "statusCode": 429,
  "message": "Too many failed login attempts. Please try again later.",
  "timestamp": "2024-02-17T16:30:00.000Z"
}
```

**Database & Business Logic Insights**

- **Tables Involved**: `users` collection
- **Relations**: None (single document lookup)
- **Transactions**: None
- **Side Effects**:
  - Failed login attempts tracked (max 5, 15-minute lock)
  - Rate limiting by IP and email identifier
  - Refresh token stored in user document (max 10 tokens)
  - Failed attempts cleared on successful login
- **Events Triggered**: None
- **Queue Jobs**: None
- **Caching**: None

**Rate Limiting Details**

- **Max Attempts**: 5 failed attempts
- **Window**: 10 minutes
- **Block Duration**: 15 minutes
- **Key Format**: `{ip}:{email}`

**Frontend Integration Notes**

```typescript
// Common mistakes to avoid:
// 1. Not storing tokens securely
// 2. Not handling different error types appropriately
// 3. Not implementing token refresh logic
// 4. Not clearing failed attempts on successful login

async function login(email: string, password: string) {
  const response = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  const data = await response.json();

  if (response.ok) {
    // Store tokens securely
    // WARNING: localStorage is vulnerable to XSS attacks
    // Consider using HttpOnly, Secure, SameSite cookies instead
    localStorage.setItem('accessToken', data.accessToken);
    localStorage.setItem('refreshToken', data.refreshToken);

    // Store user data
    localStorage.setItem('user', JSON.stringify(data.user));

    return { success: true, user: data.user };
  } else if (response.status === 403) {
    if (data.message.includes('not confirmed')) {
      return {
        success: false,
        type: 'EMAIL_NOT_CONFIRMED',
        message: data.message,
      };
    } else if (data.message.includes('locked')) {
      return { success: false, type: 'ACCOUNT_LOCKED', message: data.message };
    } else if (data.message.includes('deactivated')) {
      return {
        success: false,
        type: 'ACCOUNT_DEACTIVATED',
        message: data.message,
      };
    }
  } else if (response.status === 429) {
    return { success: false, type: 'RATE_LIMITED', message: data.message };
  } else {
    return {
      success: false,
      type: 'INVALID_CREDENTIALS',
      message: data.message,
    };
  }
}
```

#### POST `/auth/logout` - Logout a user

**Basic Information**

- **HTTP Method**: POST
- **Route**: `/api/auth/logout`
- **Module**: Auth
- **Controller**: AuthController
- **Method**: `logout`

**Authentication & Authorization**

- **Authentication Required**: Yes
- **Guard**: `JwtAuthGuard`
- **Roles/Permissions**: None

**Request Details**

**Headers Required**

```text
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body (RefreshTokenDto)**

```typescript
interface RefreshTokenDto {
  refreshToken: string; // Required, valid refresh token
}
```

**Validation Rules**

- `refreshToken`: `@IsNotEmpty()`, `@IsString()`

**Example Request Body**

```json
{
  "refreshToken": "<refresh_token>"
}
```

**Response Documentation**

**Success Response (200 OK)**

- **Type**: `void`
- **Description**: Logout successful, refresh token invalidated
- **Content**: No content returned

**Error Responses**

**Unauthorized Error (401 Unauthorized)**

- **When**: Invalid or expired access token

```json
{
  "statusCode": 401,
  "message": "Unauthorized",
  "timestamp": "2024-02-17T16:30:00.000Z"
}
```

**Database & Business Logic Insights**

- **Tables Involved**: `users` collection
- **Relations**: None (single document update)
- **Transactions**: None
- **Side Effects**:
  - Specific refresh token removed from user's refreshTokens array
  - Other refresh tokens remain valid
- **Events Triggered**: None
- **Queue Jobs**: None
- **Caching**: None

**Frontend Integration Notes**

```typescript
// Common mistakes to avoid:
// 1. Not clearing all stored tokens
// 2. Not calling logout on token refresh failure
// 3. Not handling network errors during logout

async function logout(accessToken: string, refreshToken: string) {
  try {
    const response = await fetch(`${BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ refreshToken }),
    });

    // Clear local storage regardless of response
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');

    if (response.ok) {
      return { success: true };
    } else {
      // Still clear tokens but indicate server error
      return { success: false, error: 'Server logout failed' };
    }
  } catch (error) {
    // Network error - still clear local tokens
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');
    return { success: false, error: 'Network error' };
  }
}
```

#### POST `/auth/refresh` - Refresh authentication tokens

**Basic Information**

- **HTTP Method**: POST
- **Route**: `/api/auth/refresh`
- **Module**: Auth
- **Controller**: AuthController
- **Method**: `refreshTokenHandler`

**Authentication & Authorization**

- **Authentication Required**: Yes
- **Guard**: `RefreshJwtGuard`
- **Roles/Permissions**: None

**Request Details**

**Headers Required**

```text
Authorization: Bearer <refresh_token>
```

**Response Documentation**

**Success Response (200 OK)**

- **Type**: `AuthResponseDto`
- **Description**: Tokens refreshed successfully

```json
{
  "accessToken": "<access_token>",
  "refreshToken": "<refresh_token>",
  "accessTokenExpiresAt": "2024-02-19T14:07:00.000Z",
  "refreshTokenExpiresAt": "2024-02-26T14:07:00.000Z",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+1234567890"
  }
}
```

**Error Responses**

**Unauthorized Error (401 Unauthorized)**

- **When**: Invalid refresh token

```json
{
  "statusCode": 401,
  "message": "Invalid refresh token",
  "timestamp": "2024-02-17T16:30:00.000Z"
}
```

- **When**: Refresh token expired

```json
{
  "statusCode": 401,
  "message": "Refresh token has expired",
  "timestamp": "2024-02-17T16:30:00.000Z"
}
```

**Database & Business Logic Insights**

- **Tables Involved**: `users` collection
- **Relations**: None (single document lookup and update)
- **Transactions**: None
- **Side Effects**:
  - Old refresh token replaced with new one
  - Expired tokens automatically cleaned up
  - Max 10 refresh tokens per user maintained
- **Events Triggered**: None
- **Queue Jobs**: None
- **Caching**: None

**Token Management Details**

- **Access Token Expiry**: 24 hours
- **Refresh Token Expiry**: 7 days
- **Max Refresh Tokens**: 10 per user
- **Cleanup**: Expired tokens removed automatically

**Frontend Integration Notes**

```typescript
// Common mistakes to avoid:
// 1. Not storing new tokens after refresh
// 2. Not handling refresh token expiration
// 3. Not implementing automatic retry logic
// 4. Not redirecting to login on refresh failure

async function refreshTokens(refreshToken: string) {
  try {
    const response = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${refreshToken}`,
      },
    });

    if (response.ok) {
      const data = await response.json();

      // Update stored tokens
      // WARNING: localStorage is vulnerable to XSS attacks
      // Consider using HttpOnly, Secure, SameSite cookies instead
      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('refreshToken', data.refreshToken);

      return { success: true, tokens: data };
    } else {
      const error = await response.json();

      // Clear tokens and redirect to login
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('user');

      return {
        success: false,
        requiresLogin: true,
        error: error.message,
      };
    }
  } catch (error) {
    // Network error - try once more then redirect
    return { success: false, requiresLogin: true, error: 'Network error' };
  }
}

// Automatic token refresh wrapper
async function makeAuthenticatedRequest(
  url: string,
  options: RequestInit = {}
) {
  let accessToken = localStorage.getItem('accessToken');
  let refreshToken = localStorage.getItem('refreshToken');

  if (!accessToken || !refreshToken) {
    throw new Error('No tokens available');
  }

  // Try original request
  let response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${accessToken}`,
    },
  });

  // If unauthorized, try refresh
  if (response.status === 401) {
    const refreshResult = await refreshTokens(refreshToken);

    if (refreshResult.success) {
      // Retry with new token
      accessToken = localStorage.getItem('accessToken')!;
      response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          Authorization: `Bearer ${accessToken}`,
        },
      });
    }
  }

  return response;
}
```

```
{
  "email": "john.doe.full@example.com",
  "password": "new_password",
  "firstName": "John",
  "lastName": "Doe",
  "birthdate": "2000-01-01",
  "phoneNumber": "+1234567890",
  "profilePicture": "<base64 string>"
}
```

**Success Response:**

```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe_full",
    "firstName": "John",
    "lastName": "Doe",
    "birthdate": "2000-01-01",
    "dateJoined": "2023-10-22T14:48:00Z",
    "profilePicture": "<base64 string>",
    "emailConfirmed": false
  }
}
```

**Validation Error Response:**

```json
{
  "errors": {
    "email": "invalid email format",
    "username": "username must be at least 5 characters"
  }
}
```

**Conflict Response:**

```json
{
  "message": "Username is already taken"
}
```

```json
{
  "message": "Email is already registered"
}
```

**Example Usage:**

```typescript
const UpdatedUser: User = {
  username: 'john_doe_full',
  email: 'john.doe.full@example.com',
  password: 'new_password',
  firstName: 'John',
  lastName: 'Doe',
};

async function updateUser(accessToken: string, user: User) {
  const response = await fetch(`${BASE_URL}/update`, {
    method: 'PUT', // or 'PATCH'
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(user),
  });

  if (!response.ok) {
    throw new Error('Update failed');
  }

  const data = await response.json();
  return data;
}

updateUser('your_access_token_here', UpdatedUser)
  .then((data) => console.log(data))
  .catch((error) => console.error(error));
```

**DELETE** `/delete` - Deletes a user
Deletes a user from the system. Requires authentication.

**Request:**

**_Authorization Header:_**
`Authorization: Bearer <your_access_token_here>`

**Success Response:**

```json
{
  "message": "Account deleted successfully"
}
```

**Example Usage:**

```typescript
async function deleteUser(accessToken: string) {
  const response = await fetch(`${BASE_URL}/delete`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error('Delete failed');
  }

  const data = await response.json();
  return data;
}

deleteUser('your_access_token_here')
  .then((data) => console.log(data))
  .catch((error) => console.error(error));
```

**POST** `/refresh` - Refreshes an access token
Refreshes an access token and returns new tokens. Requires a valid refresh token.

**Request:**

**_Authorization Header:_**
`Authorization: Bearer <your_refresh_token_here>`

**Success Response:**

```json
{
  "accessToken": "<new_access_token>",
  "refreshToken": "<new_refresh_token>",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+1234567890"
  }
}
```

**Password Reset**

**POST** `/forgot-password` - Initiate password reset

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Success Response:**

```json
{
  "message": "If an account exists with this email, a reset link will be sent"
}
```

**Validation Error Response:**

```json
{
  "errors": {
    "email": "invalid email format"
  }
}
```

**POST** `/reset-password` - Confirm password reset

**Request Body:**

```json
{
  "token": "<reset_token>",
  "newPassword": "newPassword123!"
}
```

**Success Response:**

```json
{
  "message": "Password reset successfully"
}
```

**Validation Error Response:**

```json
{
  "errors": {
    "token": "invalid token format",
    "newPassword": "password must contain at least one uppercase, lowercase, number, or special character"
  }
}
```

#### GET `/auth/confirm-email/:token` - Confirm email address

Confirms a user's email address using a token. Returns HTML page instead of JSON.

**URL Parameters:**

- `token` (string): Email confirmation token

**Success Response (200 OK):**
Returns HTML confirmation page with success message and styling.

**Error Response (200 OK):**
Returns HTML confirmation page with error message and styling.

**Example:**

```
GET http://localhost:3000/api/auth/confirm-email/abc123def456
```

**Frontend Integration:**
This endpoint is designed to be opened directly in a browser from the email confirmation link. It returns a user-friendly HTML page instead of JSON for better user experience.

**GET** `/resend-confirmation-email` - Resend confirmation email

**Request:**

**_Authorization Header:_**
`Authorization: Bearer <your_access_token_here>`

**Success Response:**

```json
{
  "message": "Confirmation email sent successfully"
}
```

**Error Response:**

```json
{
  "message": "Email is already confirmed"
}
```

**User Profile**

**GET** `/fetchuser` - Fetch current user profile

**Request:**

**_Authorization Header:_**
`Authorization: Bearer <your_access_token_here>`

**Success Response:**

```json
{
  "message": "User profile retrieved successfully",
  "user": {
    "username": "john_doe",
    "firstName": "John",
    "lastName": "Doe",
    "birthdate": "2000-01-01",
    "dateJoined": "2023-10-22T14:48:00Z",
    "profilePicture": "<base64 string>",
    "emailConfirmed": true
  }
}
```

**POST** `/fetchuserbyid` - Fetch user by ID

**Request:**

**_Authorization Header:_**
`Authorization: Bearer <your_access_token_here>`

**Request Body:**

```json
{
  "userId": "615f2e0a6c6d5c0e1a1e4a01"
}
```

**Success Response:**

```json
{
  "message": "User fetched successfully",
  "user": {
    "username": "john_doe",
    "firstName": "John",
    "lastName": "Doe",
    "birthdate": "2000-01-01",
    "dateJoined": "2023-10-22T14:48:00Z",
    "profilePicture": "<base64 string>",
    "emailConfirmed": true
  }
}
```

**POST** `/logout` - Logout a user

**Request:**

**_Authorization Header:_**
`Authorization: Bearer <your_access_token_here>`

**Request Body:**

```json
{
  "refreshToken": "<refresh_token>"
}
```

**Success Response:**
No content, successful logout.

### Error Handling

All validation errors are returned as an `errors` object mapping field names to error messages. Authentication and other errors are returned as a `message` string.

### Security & Best Practices

- All sensitive endpoints are protected by JWT authentication.
- Email confirmation is required before login.
- Brute-force protection is enforced on login (rate limiting by IP and identifier).
- Passwords must meet complexity requirements.
- Email and username uniqueness is enforced on registration and update.
- All error responses are designed for easy frontend parsing.

## TypeScript Interfaces for Frontend Integration

### AuthResponseDto

```typescript
interface AuthResponseDto {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: string; // ISO 8601 datetime (e.g., "2024-02-19T14:07:00.000Z")
  refreshTokenExpiresAt: string; // ISO 8601 datetime (e.g., "2024-02-26T14:07:00.000Z")
  user: {
    id: string;
    username: string;
    email: string;
    firstName?: string;
    lastName?: string;
    phoneNumber?: string;
  };
}
```

### RegistrationResponseDto

```typescript
interface RegistrationResponseDto {
  message: string;
  email: string;
}
```

### LoginDto

```typescript
interface LoginDto {
  email: string;
  password: string;
}
```

### RefreshTokenDto

```typescript
interface RefreshTokenDto {
  refreshToken: string;
}
```

### Token Management Usage Examples

```typescript
// Store tokens with expiry information
const loginResponse = await login(email, password);
localStorage.setItem('accessToken', loginResponse.accessToken);
localStorage.setItem('refreshToken', loginResponse.refreshToken);
localStorage.setItem(
  'accessTokenExpiresAt',
  loginResponse.accessTokenExpiresAt
);
localStorage.setItem(
  'refreshTokenExpiresAt',
  loginResponse.refreshTokenExpiresAt
);

// Check if token is expired
const isTokenExpired = (expiresAt: string): boolean => {
  return new Date(expiresAt) < new Date();
};

// Auto-refresh logic
const checkAndRefreshToken = async () => {
  const expiresAt = localStorage.getItem('accessTokenExpiresAt');
  if (expiresAt && isTokenExpired(expiresAt)) {
    // Refresh token logic here
    await refreshToken();
  }
};
```

// Calculate when tokens expire
const getExpiryTime = (expiresIn: string): Date => {
const now = new Date();
if (expiresIn === '24h') {
return new Date(now.getTime() + 24 _ 60 _ 60 _ 1000);
} else if (expiresIn === '7d') {
return new Date(now.getTime() + 7 _ 24 _ 60 _ 60 \* 1000);
}
return now;
};

// Check if token needs refresh
const needsRefresh = (expiresIn: string): boolean => {
const expiry = getExpiryTime(expiresIn);
const fiveMinutesFromNow = new Date(Date.now() + 5 _ 60 _ 1000);
return expiry <= fiveMinutesFromNow;
};

// Automatic refresh logic
if (needsRefresh('24h')) {
const refreshResponse = await refreshTokens(refreshToken);
// Update stored tokens and expiry times
}

```

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
