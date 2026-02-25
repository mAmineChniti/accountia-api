import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class TwoFAVerifyDto {
  @ApiProperty({ description: 'TOTP code from authenticator app' })
  @IsString()
  @IsNotEmpty()
  code: string;
}
