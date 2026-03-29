import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import {
  SendEmailDto,
  SendEmailResponseDto,
  EmailType,
} from '@/email/dto/send-email.dto';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private configService: ConfigService) {
    this.initializeTransporter();
  }

  private initializeTransporter(): void {
    const gmailUsername = this.configService.get<string>('GMAIL_USERNAME');
    const gmailAppPassword =
      this.configService.get<string>('GMAIL_APP_PASSWORD');
    const smtpHost = this.configService.get<string>('SMTP_HOST');
    const smtpPort = this.configService.get<number>('SMTP_PORT');

    if (gmailUsername && gmailAppPassword) {
      // Use Gmail SMTP
      this.transporter = nodemailer.createTransport({
        host: smtpHost || 'smtp.gmail.com',
        port: smtpPort || 587,
        secure: false, // true for 465, false for other ports
        auth: {
          user: gmailUsername,
          pass: gmailAppPassword,
        },
      });
      this.logger.log('Email transporter initialized with Gmail SMTP');
    } else {
      this.logger.warn(
        'Email credentials not configured. Email sending will not work.'
      );
    }
  }

  async sendEmail(sendEmailDto: SendEmailDto): Promise<SendEmailResponseDto> {
    try {
      if (!this.transporter) {
        return {
          success: false,
          error: 'Email service not configured',
        };
      }

      const { to, subject, html, text, metadata } = sendEmailDto;

      this.logger.debug(
        `Sending email to ${to} with type: ${metadata?.businessName}`
      );

      const info = await this.transporter.sendMail({
        from: this.configService.get<string>('GMAIL_USERNAME'),
        to,
        subject,
        html,
        text,
        // Add custom headers for tracking
        headers: {
          'X-Email-Type': metadata?.businessName || 'unknown',
          'X-Applicant-Email': metadata?.applicantEmail || 'unknown',
        },
      });

      this.logger.log(
        `Email sent successfully to ${to}. Message ID: ${info.messageId}`
      );

      return {
        success: true,
        messageId: info.messageId,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send email: ${errorMessage}`,
        error instanceof Error ? error.stack : 'No stack'
      );

      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Send approval email for business application
   */
  async sendApprovalEmail(
    to: string,
    businessName: string,
    applicantName: string,
    html: string,
    text: string
  ): Promise<SendEmailResponseDto> {
    return this.sendEmail({
      to,
      subject: `Your Business Application Has Been Approved - ${businessName}`,
      html,
      text,
      type: EmailType.BUSINESS_APPROVAL,
      metadata: {
        businessName,
        applicantEmail: to,
      },
    });
  }

  /**
   * Send rejection email for business application
   */
  async sendRejectionEmail(
    to: string,
    businessName: string,
    applicantName: string,
    html: string,
    text: string
  ): Promise<SendEmailResponseDto> {
    return this.sendEmail({
      to,
      subject: `Update on Your Business Application - ${businessName}`,
      html,
      text,
      type: EmailType.BUSINESS_REJECTION,
      metadata: {
        businessName,
        applicantEmail: to,
      },
    });
  }

  /**
   * Send approval email for business application (called from BusinessService)
   */
  async sendBusinessApprovalEmail(
    to: string,
    applicantName: string,
    businessName: string
  ): Promise<SendEmailResponseDto> {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Congratulations!</h2>
        <p>Dear ${applicantName},</p>
        <p>Your business application for <strong>${businessName}</strong> has been approved!</p>
        <p>You can now access your business dashboard and manage your account.</p>
        <br/>
        <p>Best regards,<br/>The Accountia Team</p>
      </div>
    `;
    const text = `Congratulations ${applicantName}! Your business application for ${businessName} has been approved.`;

    return this.sendApprovalEmail(to, businessName, applicantName, html, text);
  }

  /**
   * Send rejection email for business application (called from BusinessService)
   */
  async sendBusinessRejectionEmail(
    to: string,
    applicantName: string,
    businessName: string,
    reviewNotes: string
  ): Promise<SendEmailResponseDto> {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Update on your Business Application</h2>
        <p>Dear ${applicantName},</p>
        <p>We have reviewed your application for <strong>${businessName}</strong>.</p>
        <p>Unfortunately, we cannot approve your application at this time.</p>
        ${reviewNotes ? `<p><strong>Feedback:</strong> ${reviewNotes}</p>` : ''}
        <br/>
        <p>Best regards,<br/>The Accountia Team</p>
      </div>
    `;
    const text = `Update on ${businessName}. Unfortunately your application was rejected. ${reviewNotes}`;

    return this.sendRejectionEmail(to, businessName, applicantName, html, text);
  }

  /**
   * Send business application confirmation email
   */
  async sendBusinessApplicationEmail(
    to: string,
    applicantName: string,
    businessName: string
  ): Promise<SendEmailResponseDto> {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Application Received</h2>
        <p>Dear ${applicantName},</p>
        <p>We have received your business application for <strong>${businessName}</strong>.</p>
        <p>Our team will review your application and get back to you within 2-3 business days.</p>
        <br/>
        <p>Best regards,<br/>The Accountia Team</p>
      </div>
    `;
    const text = `Dear ${applicantName}, we have received your application for ${businessName}. We will review it shortly.`;

    return this.sendEmail({
      to,
      subject: `Business Application Received - ${businessName}`,
      html,
      text,
      type: EmailType.BUSINESS_APPROVAL, // using an existing type
      metadata: { businessName, applicantEmail: to },
    });
  }

  /**
   * Send onboarding email for a new business client
   */
  async sendClientOnboardingEmail(
    to: string,
    clientName: string,
    businessName: string,
    password: string
  ): Promise<SendEmailResponseDto> {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
        <h2 style="color: #2563eb;">Welcome to Accountia!</h2>
        <p>Dear ${clientName},</p>
        <p>You have been onboarded as a client for <strong>${businessName}</strong> on Accountia.</p>
        <p>You can now log in to view and manage your invoices using the following credentials:</p>
        <div style="background-color: #f9fafb; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 5px 0;"><strong>Email:</strong> ${to}</p>
          <p style="margin: 5px 0;"><strong>Password:</strong> <code style="background: #e5e7eb; padding: 2px 4px; border-radius: 4px;">${password}</code></p>
        </div>
        <p>Please change your password after your first login for security reasons.</p>
        <a href="${this.configService.get('FRONTEND_URL')}/login" 
           style="display: inline-block; background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 20px;">
           Go to Login
        </a>
        <br/><br/>
        <p>Best regards,<br/>The Accountia Team</p>
      </div>
    `;
    const text = `Welcome ${clientName}! You have been added as a client for ${businessName}. Your credentials: Email: ${to}, Password: ${password}. Log in at Accountia.`;

    return this.sendEmail({
      to,
      subject: `Welcome to Accountia - Your Client Account for ${businessName}`,
      html,
      text,
      type: EmailType.BUSINESS_APPROVAL,
      metadata: { businessName, applicantEmail: to },
    });
  }

  /**
   * Test email sending (for debugging)
   */
  async testEmail(to: string): Promise<SendEmailResponseDto> {
    return this.sendEmail({
      to,
      subject: 'Test Email from Accountia',
      html: '<p>This is a test email</p>',
      text: 'This is a test email',
      type: EmailType.BUSINESS_APPROVAL,
      metadata: {
        businessName: 'Test',
      },
    });
  }
}
