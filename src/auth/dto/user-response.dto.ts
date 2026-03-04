import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Role } from '@/auth/enums/role.enum';

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

  @ApiProperty({ enum: Role, enumName: 'Role', example: Role.CLIENT })
  role: Role;
}

export class PrivateUserDto extends PublicUserDto {
  @ApiProperty({ example: 'john@example.com' })
  email: string;

  @ApiPropertyOptional({ example: '+1234567890' })
  phoneNumber?: string;
}

export class UserResponseDto {
  @ApiProperty({ example: 'User profile retrieved successfully' })
  message: string;

  @ApiProperty({ type: PublicUserDto })
  user: PublicUserDto;
}

export class PrivateUserResponseDto {
  @ApiProperty({ example: 'User profile retrieved successfully' })
  message: string;

  @ApiProperty({ type: PrivateUserDto })
  user: PrivateUserDto;
}

export class MessageResponseDto {
  @ApiProperty({ example: 'Operation completed successfully' })
  message: string;
}
