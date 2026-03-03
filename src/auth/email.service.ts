import { Injectable } from '@nestjs/common';
import { readFile } from 'node:fs/promises';
import { createTransport } from 'nodemailer';

// HTML escape utility
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
  };
  return text.replaceAll(/["&'/<>]/g, (char) => map[char]);
}

// URL validation utility
function validateUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'mailto:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

@Injectable()
export class EmailService {
  private readonly from: string;
  private readonly password: string;
  private readonly smtpHost: string;
  private readonly smtpPort: string;
  private readonly frontendUrl: string;
  private readonly apiUrl: string;

  constructor() {
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
      await transporter.sendMail(mailOptions);
    } catch (error: unknown) {
      throw new Error(
        `Failed to send email: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  async sendBusinessApplicationEmail(
    userEmail: string,
    firstName: string,
    lastName: string,
    businessName: string,
    businessType: string,
    description: string,
    website?: string
  ): Promise<void> {
    const adminEmail = this.from; // Send to admin (GMAIL_USERNAME)

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">New Business Application</h2>
        <p>A user has applied for Business Owner access:</p>
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
          <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">User</td><td style="padding: 8px; border: 1px solid #ddd;">${escapeHtml(firstName)} ${escapeHtml(lastName)} (${escapeHtml(userEmail)})</td></tr>
          <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Business Name</td><td style="padding: 8px; border: 1px solid #ddd;">${escapeHtml(businessName)}</td></tr>
          <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Business Type</td><td style="padding: 8px; border: 1px solid #ddd;">${escapeHtml(businessType)}</td></tr>
          <tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Description</td><td style="padding: 8px; border: 1px solid #ddd;">${escapeHtml(description)}</td></tr>
          ${website && validateUrl(website) ? `<tr><td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Website</td><td style="padding: 8px; border: 1px solid #ddd;"><a href="${escapeHtml(website)}">${escapeHtml(website)}</a></td></tr>` : ''}
        </table>
        <p>To approve this application, update the user's role from CLIENT to BUSINESS_OWNER in the admin dashboard.</p>
      </div>
    `;

    await this.sendEmail(
      adminEmail,
      `Business Application: ${businessName} — ${firstName} ${lastName}`,
      html
    );
  }

  async sendBusinessApplicationConfirmationEmail(
    userEmail: string,
    firstName: string,
    businessName: string
  ): Promise<void> {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
        <div style="background-color: #fff; border-radius: 8px; padding: 30px; border: 1px solid #e0e0e0;">
          <h2 style="color: #7b2c2c; margin-top: 0;">✅ Application Received!</h2>
          <p>Hello <strong>${firstName}</strong>,</p>
          <p>Thank you for applying for Business Owner access on <strong>Accountia</strong>.</p>
          <p>We have received your application for <strong>${businessName}</strong> and our team will review it within <strong>2–3 business days</strong>.</p>
          <p>Once approved, your account role will be upgraded to <strong>Business Owner</strong> and you will be notified by email.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;" />
          <p style="color: #888; font-size: 13px;">If you have any questions, please contact our support team.</p>
          <p style="color: #888; font-size: 13px;">— The Accountia Team</p>
        </div>
      </div>
    `;

    await this.sendEmail(
      userEmail,
      `Your Business Application for ${businessName} — Accountia`,
      html
    );
  }
}
