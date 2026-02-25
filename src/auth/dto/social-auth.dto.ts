import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class SocialAuthDto {
  @ApiProperty({ example: 'firebase-id-token' })
  @IsString()
  @IsNotEmpty()
  idToken: string;
}
