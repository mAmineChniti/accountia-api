import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  SendEmailDto,
  SendEmailResponseDto,
  EmailType,
} from '@/email/dto/send-email.dto';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;
  private readonly frontendUrl: string;
  private readonly apiUrl: string;

  constructor(private configService: ConfigService) {
    this.initializeTransporter();
    this.frontendUrl =
      this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:3000';

    const port = this.configService.get<string>('PORT') ?? '4789';
    const host = this.configService.get<string>('APP_HOST') ?? 'localhost';
    const protocol = host === 'localhost' ? 'http' : 'https';
    this.apiUrl = `${protocol}://${host}:${port}`;
  }

  private initializeTransporter(): void {
    const gmailUsername = this.configService.get<string>('GMAIL_USERNAME');
    const gmailAppPassword =
      this.configService.get<string>('GMAIL_APP_PASSWORD');
    const smtpHost =
      this.configService.get<string>('SMTP_HOST') ?? 'smtp.gmail.com';
    const smtpPort = this.configService.get<number>('SMTP_PORT') ?? 587;

    if (gmailUsername && gmailAppPassword) {
      this.transporter = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: false,
        auth: {
          user: gmailUsername,
          pass: gmailAppPassword,
        },
      });
      this.logger.log('Email transporter initialized successfully');
    } else {
      this.logger.warn('Email credentials missing. Email sending is disabled.');
    }
  }

  /**
   * Core send method
   */
  async sendEmail(sendEmailDto: SendEmailDto): Promise<SendEmailResponseDto> {
    try {
      if (!this.transporter) {
        this.logger.error('Cannot send email: Transporter not initialized');
        return { success: false, error: 'Email service not configured' };
      }

      const { to, subject, html, text, metadata } = sendEmailDto;
      const fromEmail = this.configService.get<string>('GMAIL_USERNAME');

      const info = (await this.transporter.sendMail({
        from: `Accountia <${fromEmail}>`,
        to,
        subject,
        html,
        text,
        headers: {
          'X-Email-Type': metadata?.businessName ?? 'system',
        },
      })) as { messageId: string };

      this.logger.log(
        `Email "${subject}" sent to ${to}. ID: ${info.messageId ?? 'unknown'}`
      );
      return { success: true, messageId: info.messageId ?? 'unknown' };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to send email to ${sendEmailDto.to}: ${msg}`);
      return { success: false, error: msg };
    }
  }

  // --- Auth & System Emails ---

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    const confirmationLink = `${this.apiUrl}/api/auth/confirm-email/${token}`;
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/confirmation_email.html'
      );
      let html = await readFile(templatePath, 'utf8');

      html = html
        .replaceAll('{{.ConfirmationLink}}', confirmationLink)
        .replaceAll('{{.Year}}', new Date().getFullYear().toString());

      await this.sendEmail({
        to: email,
        subject: 'Confirm Your Accountia Account',
        html,
        text: `Please confirm your Accountia account by visiting: ${confirmationLink}`,
        type: EmailType.SYSTEM,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Confirmation email failed: ${msg}`);
    }
  }

  async sendPasswordResetEmail(
    email: string,
    resetToken: string
  ): Promise<void> {
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/password_reset.html'
      );
      let html = await readFile(templatePath, 'utf8');

      html = html
        .replaceAll('{{.Token}}', resetToken)
        .replaceAll('{{.FrontendUrl}}', this.frontendUrl)
        .replaceAll('{{.Year}}', new Date().getFullYear().toString());

      await this.sendEmail({
        to: email,
        subject: 'Password Reset Request for Accountia',
        html,
        text: `You requested a password reset. Use this token: ${resetToken}`,
        type: EmailType.SYSTEM,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Password reset email failed: ${msg}`);
    }
  }

  // --- Business Application Emails ---

  async sendBusinessApplicationEmail(
    to: string,
    applicantName: string,
    businessName: string
  ): Promise<void> {
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/business_application_submitted.html'
      );
      let html = await readFile(templatePath, 'utf8');

      html = html
        .replaceAll('{{.BusinessName}}', EmailService.escapeHtml(businessName))
        .replaceAll('{{.Year}}', new Date().getFullYear().toString());

      await this.sendEmail({
        to,
        subject: `Business Application Received: ${businessName}`,
        html,
        text: `We have received your application for ${businessName}.`,
        type: EmailType.SYSTEM,
        metadata: { businessName },
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Application submission email failed: ${msg}`);
    }
  }

  async sendBusinessApprovalEmail(
    to: string,
    applicantName: string,
    businessName: string
  ): Promise<void> {
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/business_application_approved.html'
      );
      let html = await readFile(templatePath, 'utf8');

      html = html
        .replaceAll('{{.BusinessName}}', EmailService.escapeHtml(businessName))
        .replaceAll('{{.FrontendUrl}}', this.frontendUrl)
        .replaceAll('{{.Year}}', new Date().getFullYear().toString());

      await this.sendEmail({
        to,
        subject: `Business Application Approved: ${businessName}`,
        html,
        text: `Congratulations! Your application for ${businessName} was approved.`,
        type: EmailType.BUSINESS_APPROVAL,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Approval email failed: ${msg}`);
    }
  }

  async sendBusinessRejectionEmail(
    to: string,
    applicantName: string,
    businessName: string,
    reviewNotes?: string
  ): Promise<void> {
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/business_application_rejected.html'
      );
      let html = await readFile(templatePath, 'utf8');

      html = html
        .replaceAll('{{.BusinessName}}', EmailService.escapeHtml(businessName))
        .replaceAll(
          '{{.ReviewNotes}}',
          EmailService.escapeHtml(reviewNotes ?? 'No specific reason provided')
        )
        .replaceAll('{{.FrontendUrl}}', this.frontendUrl)
        .replaceAll('{{.Year}}', new Date().getFullYear().toString());

      await this.sendEmail({
        to,
        subject: `Business Application Update: ${businessName}`,
        html,
        text: `Your application for ${businessName} was rejected. Note: ${reviewNotes}`,
        type: EmailType.BUSINESS_REJECTION,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Rejection email failed: ${msg}`);
    }
  }

  // --- Client & Invoice Emails ---

  async sendClientOnboardingEmail(
    to: string,
    clientName: string,
    businessName: string,
    tempPassword: string
  ): Promise<void> {
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/client_onboarding.html'
      );
      let html = await readFile(templatePath, 'utf8');

      const replacements = {
        '{{.ClientName}}': EmailService.escapeHtml(clientName),
        '{{.BusinessName}}': EmailService.escapeHtml(businessName),
        '{{.TempPassword}}': tempPassword,
        '{{.Email}}': EmailService.escapeHtml(to),
        '{{.LoginUrl}}': this.frontendUrl,
        '{{.Year}}': new Date().getFullYear().toString(),
      };

      for (const [placeholder, value] of Object.entries(replacements)) {
        html = html.replaceAll(placeholder, value);
      }

      await this.sendEmail({
        to,
        subject: `Welcome to ${businessName} - Your Account is Ready`,
        html,
        text: `Welcome to ${businessName}. Your temp password is: ${tempPassword}`,
        type: EmailType.ONBOARDING,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Client onboarding email failed: ${msg}`);
    }
  }

  async sendInvoiceNotification(
    to: string,
    invoiceNumber: string,
    amount: number,
    currency: string,
    dueDate: Date,
    businessName: string,
    customMessage?: string
  ): Promise<void> {
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/invoice_sent.html'
      );
      let html = await readFile(templatePath, 'utf8');

      const formattedDate = new Date(dueDate).toLocaleDateString('fr-TN', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      });

      const customMessageBlock = customMessage
        ? `<div style="background-color:#eff6ff;border-left:4px solid #8B0000;border-radius:0 8px 8px 0;padding:16px 20px;margin:20px 0;">
             <p style="font-size:13px;font-weight:600;color:#6b7280;text-transform:uppercase;margin-bottom:4px;">Message from ${EmailService.escapeHtml(businessName)}</p>
             <p style="font-size:15px;color:#374151;margin:0;">${EmailService.escapeHtml(customMessage)}</p>
           </div>`
        : '';

      const replacements = {
        '{{.BusinessName}}': EmailService.escapeHtml(businessName),
        '{{.InvoiceNumber}}': EmailService.escapeHtml(invoiceNumber),
        '{{.DueDate}}': formattedDate,
        '{{.Amount}}': amount.toFixed(2),
        '{{.Currency}}': currency,
        '{{.LoginUrl}}': `${this.frontendUrl}/login`,
        '{{.Year}}': new Date().getFullYear().toString(),
        '{{.CustomMessage}}': customMessageBlock,
      };

      for (const [placeholder, value] of Object.entries(replacements)) {
        html = html.replaceAll(placeholder, value);
      }

      await this.sendEmail({
        to,
        subject: `New Invoice from ${businessName}: ${invoiceNumber}`,
        html,
        text: `New invoice ${invoiceNumber} for ${amount} ${currency} from ${businessName}.`,
        type: EmailType.INVOICE_REMINDER,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Invoice notification email failed: ${msg}`);
    }
  }

  async sendInvoiceReminderEmail(
    to: string,
    clientName: string,
    businessName: string,
    invoiceNumber: string,
    amount: string,
    dueDate: string,
    intervalDays: number
  ): Promise<void> {
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/invoice_reminder.html'
      );
      let html = await readFile(templatePath, 'utf8');

      let title = 'Payment Reminder';
      let message = `This is a reminder regarding invoice <strong>${invoiceNumber}</strong>. Please ensure payment is made at your earliest convenience.`;
      let subject = `Reminder: Invoice ${invoiceNumber} from ${businessName}`;

      switch (intervalDays) {
        case 5: {
          title = 'Gentle Reminder';
          subject = `Gentle Reminder: Invoice ${invoiceNumber} is Overdue`;
          message = `Invoice <strong>${invoiceNumber}</strong> for <strong>${amount}</strong> was due on ${dueDate} and is now 5 days overdue.`;

          break;
        }
        case 10: {
          title = 'Account Overdue';
          subject = `Important: Account Overdue - Invoice ${invoiceNumber}`;
          message = `Invoice <strong>${invoiceNumber}</strong> for <strong>${amount}</strong> is 10 days past its due date.`;

          break;
        }
        case 20: {
          title = 'Final Notice';
          subject = `URGENT: Final Reminder for Invoice ${invoiceNumber}`;
          message = `Invoice <strong>${invoiceNumber}</strong> for <strong>${amount}</strong> is now 20 days overdue. Please pay immediately.`;

          break;
        }
        // No default
      }

      const replacements = {
        '{{.Title}}': title,
        '{{.ClientName}}': EmailService.escapeHtml(clientName),
        '{{.Message}}': message,
        '{{.InvoiceNumber}}': EmailService.escapeHtml(invoiceNumber),
        '{{.Amount}}': amount,
        '{{.DueDate}}': dueDate,
        '{{.ButtonLabel}}': 'Pay Now',
        '{{.BusinessName}}': EmailService.escapeHtml(businessName),
        '{{.InvoicesUrl}}': `${this.frontendUrl}/invoices/managed`,
        '{{.Year}}': new Date().getFullYear().toString(),
      };

      for (const [placeholder, value] of Object.entries(replacements)) {
        html = html.replaceAll(placeholder, value);
      }

      await this.sendEmail({
        to,
        subject,
        html,
        text: `Reminder: Invoice ${invoiceNumber} from ${businessName} is due.`,
        type: EmailType.INVOICE_REMINDER,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Invoices reminder email failed: ${msg}`);
    }
  }

  async sendInvoiceSentConfirmation(
    to: string,
    invoiceNumber: string,
    clientName: string,
    clientEmail: string,
    amount: number,
    currency: string
  ): Promise<void> {
    try {
      const year = new Date().getFullYear().toString();
      const html = `
      <!doctype html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>Invoice Sent Confirmation</title>
        <style>
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #1a1a2e; background-color: #f0f2f5; padding: 40px 20px; }
          .wrapper { max-width: 600px; margin: 0 auto; }
          .brand { text-align: center; margin-bottom: 24px; }
          .brand-name { font-size: 26px; font-weight: 700; color: #8B0000; }
          .container { background: #fff; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); overflow: hidden; }
          .header-bar { background: #16a34a; padding: 32px 40px; text-align: center; }
          .header-bar h1 { color: #fff; font-size: 22px; font-weight: 600; }
          .body { padding: 40px; }
          .body p { font-size: 15px; color: #374151; margin-bottom: 16px; }
          .info-box { background: #f0fdf4; border-left: 4px solid #16a34a; border-radius: 0 8px 8px 0; padding: 20px 24px; margin: 24px 0; }
          .info-row { display: flex; justify-content: space-between; margin-bottom: 8px; }
          .info-label { color: #64748b; font-size: 13px; text-transform: uppercase; font-weight: 600; }
          .info-value { color: #1e293b; font-weight: 600; font-size: 15px; }
          .footer { text-align: center; padding: 24px 40px; border-top: 1px solid #f1f5f9; font-size: 12px; color: #94a3b8; }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="brand"><span class="brand-name">Accountia</span></div>
          <div class="container">
            <div class="header-bar"><h1>✓ Invoice Sent Successfully</h1></div>
            <div class="body">
              <p>Your invoice has been successfully sent to your client. Here's a summary:</p>
              <div class="info-box">
                <div class="info-row"><span class="info-label">Invoice</span><span class="info-value">${EmailService.escapeHtml(invoiceNumber)}</span></div>
                <div class="info-row"><span class="info-label">Client</span><span class="info-value">${EmailService.escapeHtml(clientName)}</span></div>
                <div class="info-row"><span class="info-label">Email</span><span class="info-value">${EmailService.escapeHtml(clientEmail)}</span></div>
                <div class="info-row"><span class="info-label">Amount</span><span class="info-value" style="color:#16a34a;font-size:18px;">${amount.toFixed(2)} ${currency}</span></div>
              </div>
              <p style="font-size:13px;color:#6b7280;">The client will receive an email with the invoice details and a link to view it on their dashboard.</p>
            </div>
            <div class="footer">
              <p>&copy; ${year} Accountia. All rights reserved.</p>
              <p>This is an automated confirmation &mdash; please do not reply.</p>
            </div>
          </div>
        </div>
      </body>
      </html>`;

      await this.sendEmail({
        to,
        subject: `✓ Invoice ${invoiceNumber} sent to ${clientName}`,
        html,
        text: `Invoice ${invoiceNumber} for ${amount} ${currency} successfully sent to ${clientName}.`,
        type: EmailType.SYSTEM,
      });
    } catch (error) {
      this.logger.error('Failed to send BO confirmation email:', error);
    }
  }

  private static escapeHtml(value: string | undefined): string {
    if (!value) return '';
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  async sendBusinessInviteEmail(
    to: string,
    businessName: string,
    inviterName: string,
    businessRole: string
  ): Promise<void> {
    try {
      const templatePath = path.join(
        process.cwd(),
        'src/email/templates/business_invite.html'
      );
      let html = await readFile(templatePath, 'utf8');

      const roleDisplayMap: Record<string, string> = {
        ADMIN: 'Admin/Member',
        CLIENT: 'Client',
      };
      const roleDisplay = roleDisplayMap[businessRole] || businessRole;

      // Build registration link - frontend will handle the actual registration flow
      const registerLink = `${this.frontendUrl}/en/register`;

      const replacements = {
        '{{.BusinessName}}': EmailService.escapeHtml(businessName),
        '{{.InviterName}}': EmailService.escapeHtml(inviterName),
        '{{.BusinessRole}}': EmailService.escapeHtml(roleDisplay),
        '{{.InvitedEmail}}': EmailService.escapeHtml(to),
        '{{.RegisterLink}}': registerLink, // No escaping needed for URLs
        '{{.Year}}': new Date().getFullYear().toString(),
      };

      for (const [placeholder, value] of Object.entries(replacements)) {
        html = html.replaceAll(placeholder, value);
      }

      await this.sendEmail({
        to,
        subject: `You've been invited to join ${businessName}`,
        html,
        text: `You've been invited to join ${businessName} as a ${roleDisplay}.`,
        type: EmailType.SYSTEM,
        metadata: { businessName },
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Business invite email failed: ${msg}`);
    }
  }

  /**
   * Test method
   */
  async testEmail(to: string): Promise<SendEmailResponseDto> {
    return this.sendEmail({
      to,
      subject: 'Test Email from Accountia',
      html: '<p>This is a test email</p>',
      text: 'This is a test email',
      type: EmailType.SYSTEM,
    });
  }
}
