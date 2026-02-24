/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return */
import { Injectable, BadRequestException } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { randomBytes } from 'node:crypto';

@Injectable()
export class TwoFactorService {
  /**
   * Generate OTP secret and backup codes
   */
  generateSecret(email: string): {
    secret: string;
    qrCode: string;
    backupCodes: string[];
  } {
    const secret = speakeasy.generateSecret({
      name: `Accountia (${email})`,
      issuer: 'Accountia',
      length: 32,
    });

    // Generate 10 backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      randomBytes(4).toString('hex').toUpperCase()
    );

    return {
      secret: secret.base32,
      qrCode: secret.otpauth_url ?? '',
      backupCodes,
    };
  }

  /**
   * Generate QR code from OTP secret
   */
  async generateQRCode(secret: string, email: string): Promise<string> {
    const otpauthUrl = speakeasy.otpauthURL({
      secret,
      encoding: 'base32',
      label: email,
      issuer: 'Accountia',
    });

    try {
      return await QRCode.toDataURL(otpauthUrl);
    } catch {
      throw new BadRequestException('Failed to generate QR code');
    }
  }

  /**
   * Verify OTP token
   */
  verifyToken(secret: string, token: string): boolean {
    try {
      const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 2, // Allow 2 time steps (past and future)
      });

      return verified;
    } catch {
      return false;
    }
  }

  /**
   * Verify backup code
   */
  verifyBackupCode(backupCodes: string[], code: string): boolean {
    return backupCodes.includes(code.toUpperCase());
  }

  /**
   * Remove backup code from list
   */
  removeBackupCode(backupCodes: string[], code: string): string[] {
    return backupCodes.filter((bc) => bc.toUpperCase() !== code.toUpperCase());
  }
}
