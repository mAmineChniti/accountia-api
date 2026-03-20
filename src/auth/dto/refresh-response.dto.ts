import { ApiProperty } from '@nestjs/swagger';

export class RefreshResponseDto {
  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MDMyMzAzMDMAc2RmZiIsImlkIjoiNjAzMjMwMzAzMHNkZmZmIn0.GWB6Ol3Yem...',
  })
  accessToken: string;

  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MDMyMzAzMDMAc2RmZmYiLCJ0eXBlIjoicmVmcmVzaCIsImlkIjoiNjAzMjMwMzAzMHNkZmZmIn0.a1b2c3d4...',
  })
  refreshToken: string;

  @ApiProperty({
    example: '2026-03-20T15:30:00.000Z',
    description: 'ISO 8601 timestamp when the access token expires',
  })
  accessTokenExpiresAt: string;

  @ApiProperty({
    example: '2026-03-27T14:30:00.000Z',
    description: 'ISO 8601 timestamp when the refresh token expires',
  })
  refreshTokenExpiresAt: string;
}
