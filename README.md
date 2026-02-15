# Accountia API Documentation

This is the API documentation for Accountia API. The API is a RESTful API that allows you to interact with the Accountia server. The API is used to create, read, update, and delete user data from the server.

## Base URL

http://localhost:3000/api/auth

## API Documentation UI

- The interactive Swagger UI is exposed at the `/docs` route under the API base path. For example, visit `http://localhost:3000/api/auth/docs` to view the API documentation and try endpoints.

## Authentication

Protected routes require a valid JWT token in the Authorization header as a Bearer token.

### Example Authorization Header

`Authorization: Bearer <your_jwt_token>`

## Endpoints

**POST** `/register` - Register a new user
Registers a new user in the system. Returns authentication tokens and user information or a map of validation errors.

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
  "acceptTerms": true,
  "profilePicture": "<base64 string>"
}
```

**Success Response:**

```json
{
  "accessToken": "<access_token>",
  "refreshToken": "<refresh_token>",
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

**Validation Error Response:**

```json
{
  "errors": {
    "username": "username must be at least 5 characters",
    "email": "invalid email format",
    "password": "password must contain at least one uppercase, lowercase, number, or special character"
  }
}
```

**Conflict Response:**

```json
{
  "message": "Username or email is already registered"
}
```

**Example Usage:**

```typescript
const newUser: User = {
  username: 'john_doe',
  email: 'john.doe@example.com',
  password: 'SecurePass123!',
  firstName: 'John',
  lastName: 'Doe',
  acceptTerms: true,
};

async function register(user: User) {
  const response = await fetch(`${BASE_URL}/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(user),
  });

  if (!response.ok) {
    throw new Error('Registration failed');
  }

  const data = await response.json();
  return data;
}

register(newUser)
  .then((data) => console.log(data))
  .catch((error) => console.error(error));
```

**POST** `/login` - Login a user
Logs in a user and returns user info and tokens. Returns validation errors or authentication errors as appropriate.

**Request Body:**

```json
{
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

**Success Response:**

```json
{
  "accessToken": "<access_token>",
  "refreshToken": "<refresh_token>",
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

**Validation Error Response:**

```json
{
  "errors": {
    "email": "email is required",
    "password": "password must contain at least one uppercase, lowercase, number, or special character"
  }
}
```

**Authentication Error Response:**

```json
{
  "message": "Invalid email or password"
}
```

```json
{
  "message": "Account is temporarily locked due to too many failed attempts"
}
```

```json
{
  "message": "Account is deactivated"
}
```

```json
{
  "message": "Email not confirmed. Please confirm your email before logging in."
}
```

```json
{
  "message": "Too many failed login attempts. Please try again later."
}
```

**Example Usage:**

```typescript
async function login(email: string, password: string) {
  const response = await fetch(`${BASE_URL}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    throw new Error('Login failed');
  }

  const data = await response.json();
  return data;
}

login('john.doe@example.com', 'SecurePass123!')
  .then((data) => console.log(data))
  .catch((error) => console.error(error));
```

**PUT/PATCH** `/update` - Update user details
Updates a user's details. Returns updated user info or validation errors.

**Request Body:**

```json
{
  "username": "john_doe_full",
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

**Email Verification**

**GET** `/confirm-email/:token` - Confirm email address

**URL Parameters:**

- `token` (string): Email confirmation token

**Success Response:**

```json
{
  "success": true,
  "message": "Email confirmed successfully"
}
```

**Error Response:**

```json
{
  "success": false,
  "message": "Invalid confirmation token"
}
```

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

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
