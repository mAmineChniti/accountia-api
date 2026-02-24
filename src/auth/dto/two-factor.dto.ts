import { IsString, Length } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class VerifyOtpDto {
  @ApiProperty({ example: '123456', description: 'OTP code (6 digits)' })
  @IsString()
  @Length(6, 6)
  code: string;
}

export class TwoFactorSetupResponseDto {
  @ApiProperty({ example: 'JBSWY3DPEBLW64TMMQ======' })
  secret: string;

  @ApiProperty({
    example:
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAH0AAAB9CAYAAACPg...',
  })
  qrCode: string;

  @ApiProperty({
    example: ['A1B2C3D4E5', 'F6G7H8I9J0', 'K1L2M3N4O5'],
    description: 'Backup codes (10 codes)',
    isArray: true,
    type: String,
  })
  backupCodes: string[];
}

export class TwoFactorStatusDto {
  @ApiProperty({ example: true })
  twoFactorEnabled: boolean;

  @ApiPropertyOptional({ example: '2024-02-24T12:00:00Z' })
  enabledAt?: Date;
}
