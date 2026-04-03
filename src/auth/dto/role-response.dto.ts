import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@/auth/enums/role.enum';

export class RoleResponseDto {
  @ApiProperty({ example: 'User role updated successfully' })
  message: string;

  @ApiProperty({ example: '507f1f77bcf86cd799439011' })
  userId: string;

  @ApiProperty({ enum: Role, enumName: 'Role', example: Role.PLATFORM_ADMIN })
  newRole: Role;

  @ApiProperty({ enum: Role, enumName: 'Role', example: Role.CLIENT })
  previousRole: Role;
}
