import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Role } from '@/auth/enums/role.enum';

class UserSummaryDto {
  @ApiProperty({ example: '507f1f77bcf86cd799439011' })
  id!: string;

  @ApiProperty({ example: 'john_doe' })
  username!: string;

  @ApiProperty({ example: 'john@example.com' })
  email!: string;

  @ApiProperty({ example: 'John' })
  firstName!: string;

  @ApiProperty({ example: 'Doe' })
  lastName!: string;

  @ApiProperty({ example: '1990-01-01T00:00:00.000Z' })
  birthdate!: Date;

  @ApiPropertyOptional({ example: 'data:image/png;base64,iVBORw0...' })
  profilePicture?: string;

  @ApiPropertyOptional({ example: '123-456-7890' })
  phoneNumber?: string;

  @ApiProperty({ enum: Role, enumName: 'Role', example: Role.CLIENT })
  role!: Role;

  @ApiProperty({ example: '2023-01-01T00:00:00.000Z' })
  dateJoined!: Date;

  @ApiProperty({ example: false })
  isBanned!: boolean;

  @ApiPropertyOptional({ example: 'Violation of terms of service' })
  bannedReason?: string;
}

export class UsersListResponseDto {
  @ApiProperty({ example: 'Users retrieved successfully' })
  message!: string;

  @ApiProperty({ type: UserSummaryDto, isArray: true })
  users!: UserSummaryDto[];
}
