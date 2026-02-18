import { ApiProperty } from '@nestjs/swagger';

export class AuthResponseDto {
  @ApiProperty({ example: '<access_token>' })
  accessToken: string;

  @ApiProperty({ example: '<refresh_token>' })
  refreshToken: string;

  @ApiProperty({
    example: '2024-02-19T14:07:00.000Z',
    description: 'Access token expiry datetime (ISO 8601 format)',
  })
  accessTokenExpiresAt: string;

  @ApiProperty({
    example: '2024-02-26T14:07:00.000Z',
    description: 'Refresh token expiry datetime (ISO 8601 format)',
  })
  refreshTokenExpiresAt: string;

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
