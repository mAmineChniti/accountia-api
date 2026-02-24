import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ProfileResponseDto {
  @ApiProperty({ example: 'user-id-123' })
  id: string;

  @ApiProperty({ example: 'john_doe' })
  username: string;

  @ApiProperty({ example: 'john@example.com' })
  email: string;

  @ApiProperty({ example: 'John' })
  firstName: string;

  @ApiProperty({ example: 'Doe' })
  lastName: string;

  @ApiProperty({ example: '1990-01-15' })
  birthdate: Date;

  @ApiPropertyOptional({ example: '+1234567890', nullable: true })
  phoneNumber?: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ example: true })
  emailConfirmed: boolean;

  @ApiPropertyOptional({
    example: 'https://example.com/profile.jpg',
    nullable: true,
  })
  profilePicture?: string;

  @ApiPropertyOptional({ example: '2024-01-15T10:00:00Z' })
  createdAt?: Date;

  @ApiPropertyOptional({ example: '2024-01-15T10:00:00Z' })
  updatedAt?: Date;
}
