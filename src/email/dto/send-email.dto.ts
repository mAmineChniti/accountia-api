import {
  IsEmail,
  IsString,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  Allow,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum EmailType {
  BUSINESS_APPROVAL = 'business_approval',
  BUSINESS_REJECTION = 'business_rejection',
  INVOICE_REMINDER = 'invoice_reminder',
  SYSTEM = 'system',
  ONBOARDING = 'onboarding',
}

export class SendEmailDto {
  @ApiProperty({
    description: 'Recipient email address',
    example: 'applicant@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  to: string;

  @ApiProperty({
    description: 'Email subject',
    example: 'Your Business Application Has Been Approved',
  })
  @IsString()
  @IsNotEmpty()
  subject: string;

  @ApiProperty({
    description: 'HTML email content',
    example: '<html><body>Your business has been approved</body></html>',
  })
  @IsString()
  @IsNotEmpty()
  html: string;

  @ApiProperty({
    description: 'Plain text email content',
    example: 'Your business has been approved',
  })
  @IsString()
  @IsNotEmpty()
  text: string;

  @ApiProperty({
    enum: EmailType,
    enumName: 'EmailType',
    description: 'Type of email being sent',
    example: EmailType.BUSINESS_APPROVAL,
  })
  @IsEnum(EmailType)
  @IsNotEmpty()
  type: EmailType;

  @ApiPropertyOptional({
    description: 'Metadata for email tracking',
    example: {
      businessName: 'Acme Corp',
      applicantEmail: 'applicant@example.com',
    },
  })
  @Allow()
  @IsOptional()
  metadata?: {
    businessName?: string;
    applicantEmail?: string;
    [key: string]: unknown;
  };
}

export class SendEmailResponseDto {
  @ApiProperty({
    description: 'Whether email was sent successfully',
    example: true,
  })
  success: boolean;

  @ApiPropertyOptional({
    description: 'Email service message ID (optional)',
    example: 'msg_xyz123',
  })
  messageId?: string;

  @ApiPropertyOptional({
    description: 'Error message if sending failed',
    example: 'SMTP connection failed',
  })
  error?: string;
}
