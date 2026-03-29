import { Injectable } from '@nestjs/common';
import { readFile } from 'node:fs/promises';
import { createTransport } from 'nodemailer';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '@/users/schemas/user.schema';

@Injectable()
export class EmailService {
  private readonly from: string;
  private readonly password: string;
  private readonly smtpHost: string;
  private readonly smtpPort: string;
  private readonly frontendUrl: string;
  private readonly apiUrl: string;

  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {
    if (
      typeof process.env.GMAIL_USERNAME !== 'string' ||
      !process.env.GMAIL_USERNAME.trim()
    ) {
      throw new Error(
        'GMAIL_USERNAME environment variable is required and must be a non-empty string'
      );
    }

    if (
      typeof process.env.GMAIL_APP_PASSWORD !== 'string' ||
      !process.env.GMAIL_APP_PASSWORD.trim()
    ) {
      throw new Error(
        'GMAIL_APP_PASSWORD environment variable is required and must be a non-empty string'
      );
    }

    if (
      typeof process.env.FRONTEND_URL !== 'string' ||
      !process.env.FRONTEND_URL.trim()
    ) {
      throw new Error(
        'FRONTEND_URL environment variable is required and must be a non-empty string'
      );
    }

    this.from = process.env.GMAIL_USERNAME;
    this.password = process.env.GMAIL_APP_PASSWORD;
    this.smtpHost = process.env.SMTP_HOST ?? 'smtp.gmail.com';
    this.smtpPort = process.env.SMTP_PORT ?? '587';
    this.frontendUrl = process.env.FRONTEND_URL;

    const port = process.env.PORT ?? '4789';
    const host = process.env.APP_HOST ?? 'localhost';
    const protocol = host === 'localhost' ? 'http' : 'https';
    this.apiUrl = `${protocol}://${host}:${port}`;
  }

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    const confirmationLink = `${this.apiUrl}/api/auth/confirm-email/${token}`;

    try {
      const templatePath = `${process.cwd()}/src/auth/templates/confirmation_email.html`;
      const template = await readFile(templatePath, 'utf8');

      const year = new Date().getFullYear();
      const html = template
        .replaceAll('{{.ConfirmationLink}}', confirmationLink)
        .replaceAll('{{.Year}}', year.toString());

      await this.sendEmail(email, 'Confirm Your Accountia Account', html);
    } catch (error: unknown) {
      throw new Error(
        `Failed to send confirmation email: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  async sendPasswordResetEmail(
    email: string,
    resetToken: string
  ): Promise<void> {
    try {
      const templatePath = `${process.cwd()}/src/auth/templates/password_reset.html`;
      const template = await readFile(templatePath, 'utf8');

      const year = new Date().getFullYear();
      const html = template
        .replaceAll('{{.Token}}', resetToken)
        .replaceAll('{{.FrontendUrl}}', this.frontendUrl)
        .replaceAll('{{.Year}}', year.toString());

      await this.sendEmail(email, 'Password Reset Request for Accountia', html);
    } catch (error: unknown) {
      throw new Error(
        `Failed to send password reset email: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  async sendBusinessApplicationEmail(
    userId: string,
    businessName: string
  ): Promise<void> {
    await this.sendBusinessEmailTemplate(
      userId,
      'business_application_submitted.html',
      `Business Application Received: ${businessName}`,
      {
        '{{.BusinessName}}': EmailService.escapeHtml(businessName),
      }
    );
  }

  async sendBusinessApprovalEmail(
    userId: string,
    businessName: string
  ): Promise<void> {
    await this.sendBusinessEmailTemplate(
      userId,
      'business_application_approved.html',
      `Business Application Approved: ${businessName}`,
      {
        '{{.BusinessName}}': EmailService.escapeHtml(businessName),
        '{{.FrontendUrl}}': this.frontendUrl,
      }
    );
  }

  async sendBusinessRejectionEmail(
    userId: string,
    businessName: string,
    reviewNotes?: string
  ): Promise<void> {
    await this.sendBusinessEmailTemplate(
      userId,
      'business_application_rejected.html',
      `Business Application Update: ${businessName}`,
      {
        '{{.BusinessName}}': EmailService.escapeHtml(businessName),
        '{{.ReviewNotes}}': EmailService.escapeHtml(
          reviewNotes ?? 'No specific reason provided'
        ),
        '{{.FrontendUrl}}': this.frontendUrl,
      }
    );
  }

  async sendClientOnboardingEmail(
    email: string,
    clientName: string,
    businessName: string,
    tempPassword: string,
    clientEmail?: string
  ): Promise<void> {
    try {
      const templatePath = `${process.cwd()}/src/business/templates/client_onboarding.html`;
      console.log('Template path:', templatePath);
      let html = await readFile(templatePath, 'utf8');
      
      const year = new Date().getFullYear().toString();
      const replacements = {
        '{{.ClientName}}': EmailService.escapeHtml(clientName),
        '{{.BusinessName}}': EmailService.escapeHtml(businessName),
        '{{.TempPassword}}': tempPassword,
        '{{.Email}}': EmailService.escapeHtml(clientEmail || email),
        '{{.LoginUrl}}': this.frontendUrl,
        '{{.Year}}': year,
      };

      for (const [placeholder, value] of Object.entries(replacements)) {
        html = html.replaceAll(placeholder, value);
      }

      await this.sendEmail(email, `Welcome to ${businessName} - Your Account is Ready`, html);
    } catch (error: unknown) {
      console.error('Failed to send client onboarding email:', error);
    }
  }

  async sendInvoiceNotification(
    email: string,
    invoiceNumber: string,
    amount: number,
    currency: string,
    dueDate: Date,
    businessName: string,
    customMessage?: string,
  ): Promise<void> {
    try {
      const templatePath = `${process.cwd()}/src/auth/templates/invoice_sent.html`;
      let html = await readFile(templatePath, 'utf8');
      
      const year = new Date().getFullYear().toString();
      const dateObj = new Date(dueDate);
      const formattedDate = isNaN(dateObj.getTime()) ? 'N/A' : dateObj.toLocaleDateString('fr-TN', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      });

      // Build optional custom message block
      const customMessageBlock = customMessage 
        ? `<div style="background-color:#eff6ff;border-left:4px solid #2563eb;border-radius:0 8px 8px 0;padding:16px 20px;margin:20px 0;">
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
        '{{.Year}}': year,
        '{{.CustomMessage}}': customMessageBlock,
      };

      for (const [placeholder, value] of Object.entries(replacements)) {
        html = html.replaceAll(placeholder, value);
      }

      await this.sendEmail(email, `New Invoice from ${businessName}: ${invoiceNumber}`, html);
    } catch (error: unknown) {
      console.error('Failed to send invoice notification email:', error);
    }
  }

  /**
   * Sends a confirmation email to the Business Owner after invoice is sent
   */
  async sendInvoiceSentConfirmation(
    businessOwnerId: string,
    invoiceNumber: string,
    clientName: string,
    clientEmail: string,
    amount: number,
    currency: string,
  ): Promise<void> {
    try {
      const ownerEmail = await this.getUserEmail(businessOwnerId);
      
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

      await this.sendEmail(ownerEmail, `✓ Invoice ${invoiceNumber} sent to ${clientName}`, html);
    } catch (error: unknown) {
      console.error('Failed to send BO confirmation email:', error);
    }
  }

  private async sendBusinessEmailTemplate(
    userId: string,
    templateFile: string,
    subject: string,
    replacements: Record<string, string>
  ): Promise<void> {
    const userEmail = await this.getUserEmail(userId);
    try {
      const templatePath = `${process.cwd()}/src/business/templates/${templateFile}`;
      let html = await readFile(templatePath, 'utf8');
      const year = new Date().getFullYear().toString();
      const allReplacements = { '{{.Year}}': year, ...replacements };
      for (const [placeholder, value] of Object.entries(allReplacements)) {
        html = html.replaceAll(placeholder, value);
      }
      await this.sendEmail(userEmail, subject, html);
    } catch (error: unknown) {
      throw new Error(
        `Failed to send business email: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private static escapeHtml(value: string | undefined | null): string {
    if (!value) return '';
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  private async getUserEmail(userId: string): Promise<string> {
    try {
      const user = await this.userModel.findById(userId).select('email').lean();
      if (!user?.email) {
        throw new Error(
          `User not found or email not available for user ID: ${userId}`
        );
      }
      return user.email;
    } catch (error) {
      throw new Error(
        `Failed to fetch user email: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
  private async sendEmail(
    to: string,
    subject: string,
    htmlContent: string
  ): Promise<void> {
    const transporter = createTransport({
      host: this.smtpHost,
      port: Number.parseInt(this.smtpPort),
      secure: false,
      auth: {
        user: this.from,
        pass: this.password,
      },
    });

    const mailOptions = {
      from: `Accountia <${this.from}>`,
      to: to,
      subject: subject,
      html: htmlContent,
    };

    try {
      console.log(`Attempting to send email to: ${to} with subject: ${subject}`);
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent successfully:', info.messageId);
    } catch (error: unknown) {
      console.error('SMTP Error details:', error);
      throw new Error(
        `Failed to send email: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
}

