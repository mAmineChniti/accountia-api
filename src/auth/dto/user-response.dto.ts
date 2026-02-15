import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PublicUserDto {
  @ApiProperty({ example: 'john_doe' })
  username: string;

  @ApiProperty({ example: 'John' })
  firstName: string;

  @ApiProperty({ example: 'Doe' })
  lastName: string;

  @ApiProperty({ example: '1990-01-01T00:00:00.000Z' })
  birthdate: Date;

  @ApiProperty({ example: '2023-01-01T00:00:00.000Z' })
  dateJoined: Date;

  @ApiPropertyOptional({ example: 'data:image/png;base64,iVBORw0...' })
  profilePicture?: string;

  @ApiProperty({ example: true })
  emailConfirmed: boolean;
}

export class UserResponseDto {
  @ApiProperty({ example: 'User profile retrieved successfully' })
  message: string;

  @ApiProperty({ type: PublicUserDto })
  user: PublicUserDto;
}

export class MessageResponseDto {
  @ApiProperty({ example: 'Operation completed successfully' })
  message: string;
}

export class HealthResponseDto {
  @ApiProperty({ example: 'ok' })
  status: string;

  @ApiPropertyOptional({ type: Object })
  details?: Record<string, unknown>;
}
