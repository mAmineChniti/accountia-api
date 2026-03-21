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

  private static escapeHtml(value: string): string {
    return value
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
      await transporter.sendMail(mailOptions);
    } catch (error: unknown) {
      throw new Error(
        `Failed to send email: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
}
