# Accountia API

Complete documentation and API reference for the Accountia multi-tenant invoice and business management platform.

## 📚 Documentation

Complete documentation is organized by module. Each module contains detailed information about endpoints, request/response formats, database schemas, and integration points.

### Core Modules

| Module               | Purpose                                                    | Documentation                                                                |
| -------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- |
| **Auth**             | User authentication, registration, 2FA, profile management | [Auth Module Docs](src/auth/README.md)                                       |
| **Business**         | Business management, invites, user roles, statistics       | [Business Module Docs](src/business/README.md)                               |
| **Invoices**         | Invoice creation, management, payments, PDF generation     | [Invoices Module Docs](src/invoices/README.md)                               |
| **Products**         | Product catalog, pricing, tax management                   | [Products Module Docs](src/products/README.md)                               |
| **Email**            | Transactional emails, templates, SMTP configuration        | [Email Module Docs](src/email/README.md)                                     |
| **Users**            | User account data, schemas, authentication tracking        | [Users Module Docs](src/users/README.md)                                     |
| **Business Invites** | Email-based business invitations, auto-confirmation        | See [Business Module Docs](src/business/README.md#business-invitations-flow) |

### Real-Time & Utilities

| Module            | Purpose                                               | Documentation                                            |
| ----------------- | ----------------------------------------------------- | -------------------------------------------------------- |
| **Notifications** | WebSocket real-time notifications, subscriptions      | [Notifications Module Docs](src/notifications/README.md) |
| **Chat**          | Real-time messaging, conversations, presence tracking | [Chat Module Docs](src/chat/README.md)                   |
| **Audit**         | Audit logging, action tracking, compliance            | [Audit Module Docs](src/audit/README.md)                 |
| **Common**        | Shared utilities, filters, pipes, middleware          | [Common Module Docs](src/common/README.md)               |

## Quick Start

### Installation

```bash
bun install
```

### Environment Setup

```bash
cp .env.example .env
# Edit .env with your configuration
```

### Development

```bash
bun run dev
```

### Build

```bash
bun run build
```

### Linting

```bash
bun lint
```

## Architecture Overview

### Base URL

```text
http://localhost:3000/api
```

### Authentication Headers

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

### Multi-Tenancy

This API uses a **multi-tenant architecture** where resources are scoped to specific businesses:

- **Platform Database**: Stores users, businesses, and invites
- **Tenant Databases**: Per-business isolated data (invoices, products, chat, etc.)
- **Tenant Context**: Provided via `businessId` in request body for `TenantContextGuard`-protected routes

> For routes requiring business context, include `businessId` in the request body. Without it, you'll receive a **400 Bad Request** error.

---

## API Endpoint Organization

All API endpoints are documented in their respective module READMEs. Navigate to the module above that matches your needs:

- **Authentication & User Management** → [Auth Module](src/auth/README.md)
- **Business & Company Setup** → [Business Module](src/business/README.md)
- **Invoice Operations** → [Invoices Module](src/invoices/README.md)
- **Product Catalog** → [Products Module](src/products/README.md)
- **Email Services** → [Email Module](src/email/README.md)
- **Real-Time Notifications** → [Notifications Module](src/notifications/README.md)
- **Messaging** → [Chat Module](src/chat/README.md)
- **Audit Trail** → [Audit Module](src/audit/README.md)
- **Shared Utilities** → [Common Module](src/common/README.md)

## Error Response Format

All error responses follow a standard format:

```json
{
  "statusCode": 400,
  "message": "Bad Request",
  "detail": "Specific error message",
  "timestamp": "2024-04-07T10:30:00Z",
  "path": "/api/auth/register"
}
```

## Role Permissions

### Platform Roles

- **PLATFORM_OWNER**: Full system access, can create/delete businesses, manage admins
- **PLATFORM_ADMIN**: Administrative access, manage users and businesses
- **BUSINESS_OWNER**: Own a business, manage business users and operations
- **CLIENT**: Regular user, limited to assigned business resources

### Business Roles

- **OWNER**: Full business control
- **ADMIN**: Business administration and user management
- **MEMBER**: Can create invoices and manage operations
- **CLIENT**: View-only access to invoices

## Key Features

✅ **Multi-Tenant Architecture** - Complete data isolation per business  
✅ **Email-Based Business Invites** - Auto-confirmation on registration  
✅ **Real-Time WebSocket Notifications** - Instant updates for invoices and events  
✅ **JWT Authentication** - Secure token-based access  
✅ **2FA Support** - TOTP-based two-factor authentication  
✅ **Invoice Management** - Full lifecycle from draft to paid  
✅ **Product Catalog** - Reusable products with tax configuration  
✅ **Real-Time Chat** - Team messaging with presence tracking  
✅ **Comprehensive Audit Logging** - Track all system actions  
✅ **Google OAuth** - Social authentication support

## Development

### Prerequisites

- Node.js 18+
- MongoDB (Atlas or local)
- Bun package manager

### Configuration

See each module's documentation for specific configuration requirements. Environment variables can be set in `.env`:

```bash
# Database
MONGODB_URI=mongodb://localhost:27017/accountia
PLATFORM_DB=accountia_db

# Authentication
JWT_SECRET=your_jwt_secret
JWT_EXPIRATION=900

# Email
GMAIL_USERNAME=your_email@gmail.com
GMAIL_APP_PASSWORD=xxxx_xxxx_xxxx_xxxx

# Frontend
FRONTEND_URL=http://localhost:3001
```

## File Structure

```
src/
├── auth/                 # Authentication & user management
├── business/             # Business & company management
├── invoices/             # Invoice management
├── products/             # Product catalog
├── email/                # Email services
├── users/                # User schema & data
├── notifications/        # Real-time notifications
├── chat/                 # Messaging system
├── audit/                # Audit logging
└── common/               # Shared utilities, filters, pipes
```

## Database Schema

### Platform Database

Stores shared data across tenants:

- Users (authentication, profiles)
- Businesses (company information)
- Business Applications (onboarding flow)
- Business Invites (email-based invitations)
- Business Users (role assignments)

### Tenant Databases

Per-business isolated data:

- Invoices (personal & company)
- Products (catalog)
- Chat (conversations & messages)
- Notifications (user subscriptions)
- Audit Logs (action tracking)

## Security

- ✅ JWT token authentication with refresh token rotation
- ✅ Password hashing with bcrypt (cost factor: 10)
- ✅ 2FA/TOTP support via authenticator apps
- ✅ Rate limiting on sensitive endpoints
- ✅ CORS protection with configurable origins
- ✅ SQL injection protection via Mongoose/TypeScript
- ✅ XSS protection via input validation
- ✅ Complete audit logging of sensitive actions

## Production Readiness

- ✅ **Error Handling**: Comprehensive exception filters and error responses
- ✅ **Validation**: Input validation via class-validator
- ✅ **Logging**: Structured logging for debugging and monitoring
- ✅ **Testing**: Build passes with zero warnings
- ✅ **Documentation**: Complete API documentation per module
- ✅ **Performance**: Indexed queries, connection pooling, caching
- ✅ **Horizontal Scalability**: Stateless design for load balancing
- ✅ **Tenant Isolation**: Complete data separation per business
- ✅ **Security Audit**: No sensitive data in error messages

## Contributing

1. Create a feature branch
2. Make your changes
3. Run `bun lint` to check code style
4. Run `bun run build` to verify compilation
5. Submit a pull request

## License

Proprietary - Accountia Platform

---

**Built with ❤️ using NestJS**
