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
    example: {
      id: '1',
      username: 'john_doe',
      email: 'john@example.com',
      isAdmin: true,
      firstName: 'John',
      lastName: 'Doe',
      phoneNumber: '+1234567890',
      profilePicture: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...',
      birthdate: '1990-01-01T00:00:00.000Z',
    },
  })
  user: {
    id: string;
    username: string;
    email: string;
    firstName?: string;
    lastName?: string;
    phoneNumber?: string;
    isAdmin: boolean;
    profilePicture?: string;
    birthdate?: Date;
  };
}
