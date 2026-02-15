import { ApiProperty } from '@nestjs/swagger';

export class AuthResponseDto {
  @ApiProperty({ example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' })
  accessToken: string;

  @ApiProperty({ example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' })
  refreshToken: string;

  @ApiProperty({
    example: { id: '1', username: 'john_doe', email: 'john@example.com' },
  })
  user: {
    id: string;
    username: string;
    email: string;
    firstName?: string;
    lastName?: string;
    phoneNumber?: string;
  };
}
