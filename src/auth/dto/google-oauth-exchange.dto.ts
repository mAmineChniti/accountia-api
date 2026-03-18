import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class GoogleOAuthExchangeDto {
  @ApiProperty({
    example: 'Q5vV0A4m7s6h2P3fL9k1yN8uR0xWcBzD4eTqJmHnKpI',
    description: 'One-time OAuth code returned to frontend callback URL',
  })
  @IsString()
  @IsNotEmpty()
  @Length(16, 512)
  @Matches(/^[\w-]+$/)
  oauthCode: string;
}
