# Backend Email Integration Guide

## Overview

This guide explains the email sending implementation in the Accountia API backend.

## Setup

### 1. Dependencies

NodeMailer is already installed. No additional packages needed.

```bash
npm install  # Already includes nodemailer
```

### 2. Environment Variables

The following environment variables are required and already configured in `.env`:

```env
# Email Configuration (Gmail SMTP)
GMAIL_USERNAME=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
```

#### Getting Gmail App Password

1. Go to https://myaccount.google.com/
2. Enable 2-Factor Authentication
3. Go to App Passwords
4. Select "Mail" and "Windows Computer"
5. Copy the generated password
6. Use this password as `GMAIL_APP_PASSWORD`

### 3. Module Structure

```
src/email/
├── email.module.ts          # Module definition
├── email.controller.ts      # API endpoints
├── email.service.ts         # Email sending logic
└── dto/
    └── send-email.dto.ts    # Request/Response DTOs
```

## API Endpoints

### 1. Send Email (Main Endpoint)

**Endpoint:** `POST /email/send`

**Authentication:** Required (Bearer Token)

**Required Roles:** PLATFORM_ADMIN, PLATFORM_OWNER, BUSINESS_ADMIN, BUSINESS_OWNER

**Request Body:**

```json
{
  "to": "applicant@example.com",
  "subject": "Your Business Application Has Been Approved",
  "html": "<html><body>Your application has been approved</body></html>",
  "text": "Your application has been approved",
  "type": "business_approval",
  "metadata": {
    "businessName": "Acme Corp",
    "applicantEmail": "applicant@example.com"
  }
}
```

**Response (Success - 200):**

```json
{
  "success": true,
  "messageId": "msg_xyz123@gmail.com"
}
```

**Response (Error - 200):**

```json
{
  "success": false,
  "error": "SMTP connection failed or other error message"
}
```

### 2. Test Email

**Endpoint:** `POST /email/test`

**Authentication:** Required (Bearer Token)

**Request Body:**

```json
{
  "to": "test@example.com"
}
```

**Response:**

```json
{
  "success": true,
  "messageId": "msg_test@gmail.com"
}
```

## Database Changes

### BusinessApplication Schema Updates

Added new fields to store applicant information for email notifications:

```typescript
@Prop({ required: false })
applicantEmail?: string;  // Email for sending notifications

@Prop({ required: false })
applicantName?: string;   // Name for personalized emails
```

These fields should be populated when creating a business application from user data.

## Service Methods

### EmailService

#### `sendEmail(sendEmailDto: SendEmailDto): Promise<SendEmailResponseDto>`

Main method to send emails with full control over content.

#### `sendApprovalEmail(...): Promise<SendEmailResponseDto>`

Convenience method for sending approval notifications.

#### `sendRejectionEmail(...): Promise<SendEmailResponseDto>`

Convenience method for sending rejection notifications.

#### `testEmail(to: string): Promise<SendEmailResponseDto>`

Send a test email for debugging.

## Integration with Business Controller

When reviewing applications in the Business Controller, you should:

1. Update application status
2. Call email service to notify applicant

Example implementation:

```typescript
import { EmailService } from '@/email/email.service';

@Injectable()
export class BusinessService {
  constructor(
    private emailService: EmailService
    // ... other dependencies
  ) {}

  async reviewApplication(
    id: string,
    reviewDto: ReviewBusinessApplicationDto,
    adminId: string
  ) {
    // Update application in database
    const application = await this.applicationModel.findByIdAndUpdate(id, {
      status: reviewDto.status,
      reviewNotes: reviewDto.reviewNotes,
      reviewedBy: adminId,
    });

    // Send email notification
    if (application.applicantEmail) {
      if (reviewDto.status === 'approved') {
        await this.emailService.sendApprovalEmail(
          application.applicantEmail,
          application.businessName,
          application.applicantName || 'Applicant',
          htmlContent,
          textContent
        );
      } else {
        await this.emailService.sendRejectionEmail(
          application.applicantEmail,
          application.businessName,
          application.applicantName || 'Applicant',
          htmlContent,
          textContent
        );
      }
    }

    return application;
  }
}
```

## Error Handling

The email service handles errors gracefully:

1. If email service is not configured, it returns:

   ```json
   {
     "success": false,
     "error": "Email service not configured"
   }
   ```

2. If SMTP connection fails, it returns:

   ```json
   {
     "success": false,
     "error": "SMTP connection error message"
   }
   ```

3. Email sending failures don't block the application review process - they're logged but don't cause the API to return an error

## Logging

EmailService uses NestJS Logger for debugging:

```
[EmailService] Email transporter initialized with Gmail SMTP
[EmailService] Sending email to applicant@example.com
[EmailService] Email sent successfully. Message ID: msg_xyz@gmail.com
```

Enable debug logging with:

```env
DEBUG=*  # In development only
```

## Testing

### Manual Test with cURL

1. Get authentication token:

```bash
curl -X POST http://localhost:4789/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@accountia.com","password":"admin123"}'
```

2. Send test email:

```bash
curl -X POST http://localhost:4789/api/email/test \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to":"your-email@gmail.com"}'
```

3. Send approval email:

```bash
curl -X POST http://localhost:4789/api/email/send \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "applicant@example.com",
    "subject": "Your Business Application Has Been Approved",
    "html": "<p>Congratulations!</p>",
    "text": "Congratulations!",
    "type": "business_approval",
    "metadata": {"businessName": "Acme"}
  }'
```

### Automated Testing

Run tests:

```bash
npm test src/email/email.service.spec.ts
```

## Production Considerations

1. **Rate Limiting:** Consider implementing rate limiting to prevent email spam

2. **Email Verification:** Store delivery status for tracking

3. **Error Notifications:** Alert admins if email service fails repeatedly

4. **Template Management:** Consider using email templates stored in database

5. **Retry Logic:** Implement retry mechanism for failed sends

6. **Email Queuing:** For high-volume sends, use job queue (Bull, RabbitMQ)

Example with Bull:

```typescript
@Injectable()
export class EmailService {
  constructor(@InjectQueue('email') private emailQueue: Queue) {}

  async sendEmail(dto: SendEmailDto) {
    await this.emailQueue.add('send', dto, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }
}
```

## Troubleshooting

### Email not sending

1. Check Gmail credentials in `.env`
2. Verify Gmail account has App Passwords enabled
3. Check logs: `npm run start:dev` and look for error messages
4. Test with `/email/test` endpoint first

### SMTP Connection Error

1. Verify `SMTP_HOST` and `SMTP_PORT` are correct
2. Check if Gmail account allows less secure app access
3. Verify network connectivity to SMTP server

### Authentication Error in API

1. Ensure JWT token is valid and in correct format
2. Check user has required roles (PLATFORM_ADMIN minimum)
3. Verify Authorization header is set correctly

## Related Files

- Frontend email templates: `accountia-web/lib/email-templates.ts`
- Frontend email actions: `accountia-web/actions/email.ts`
- Database schema: `src/business/schemas/business-application.schema.ts`
