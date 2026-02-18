import { Injectable } from '@nestjs/common';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { createTransport } from 'nodemailer';

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

    const port = process.env.PORT ?? '3000';
    const host = process.env.HOSTNAME ?? 'localhost';
    const protocol = host === 'localhost' ? 'http' : 'https';
    this.apiUrl = `${protocol}://${host}:${port}`;
  }

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    const confirmationLink = `${this.apiUrl}/auth/confirm-email/${token}`;

    try {
      const templatePath = path.join(
        process.cwd(),
        'src',
        'auth',
        'templates',
        'confirmation_email.html'
      );
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
      const templatePath = path.join(
        process.cwd(),
        'src',
        'auth',
        'templates',
        'password_reset.html'
      );
      const template = await readFile(templatePath, 'utf8');

      const year = new Date().getFullYear();
      const html = template
        .replaceAll('{{.Token}}', resetToken)
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
}
