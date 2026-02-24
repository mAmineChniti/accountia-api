import { ApiProperty } from '@nestjs/swagger';

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

  @ApiProperty({ example: '+1234567890', required: false, nullable: true })
  phoneNumber?: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ example: true })
  emailConfirmed: boolean;

  @ApiProperty({ example: 'https://example.com/profile.jpg', required: false, nullable: true })
  profilePicture?: string;

  @ApiProperty({ example: '2024-01-15T10:00:00Z', required: false })
  createdAt?: Date;

  @ApiProperty({ example: '2024-01-15T10:00:00Z', required: false })
  updatedAt?: Date;
}
