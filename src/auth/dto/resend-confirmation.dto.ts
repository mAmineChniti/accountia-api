import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ResendConfirmationDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Email address to resend confirmation to',
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
