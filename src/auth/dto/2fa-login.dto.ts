import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

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
