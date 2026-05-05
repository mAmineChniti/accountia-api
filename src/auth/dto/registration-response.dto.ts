import { ApiProperty } from '@nestjs/swagger';

export class RegistrationResponseDto {
  @ApiProperty({
    example:
      'Registration successful! Please check your email to confirm your account.',
    description: 'Success message for registration',
  })
  message: string;

  @ApiProperty({
    example: 'user@example.com',
    description: 'User email address',
  })
  email: string;
}
