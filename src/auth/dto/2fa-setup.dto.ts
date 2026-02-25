import { ApiProperty } from '@nestjs/swagger';

export class TwoFASetupResponseDto {
  @ApiProperty({ description: 'QR code image (data URL)' })
  qrCode: string;

  @ApiProperty({ description: 'Manual entry key' })
  secret: string;
}
