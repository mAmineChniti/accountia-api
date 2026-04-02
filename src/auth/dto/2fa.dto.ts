import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * Request DTO for 2FA login step
 */
export class TwoFALoginDto {
  @ApiProperty({ description: 'Temporary token from login step' })
  @IsString()
  @IsNotEmpty()
  tempToken: string;

  @ApiProperty({ description: 'TOTP code from authenticator app' })
  @IsString()
  @IsNotEmpty()
  code: string;
}

/**
 * Response DTO for 2FA setup
 */
export class TwoFASetupResponseDto {
  @ApiProperty({ description: 'QR code image (data URL)' })
  qrCode: string;

  @ApiProperty({ description: 'Manual entry key' })
  secret: string;
}

/**
 * Request DTO for 2FA verification
 */
export class TwoFAVerifyDto {
  @ApiProperty({ description: 'TOTP code from authenticator app' })
  @IsString()
  @IsNotEmpty()
  code: string;
}
