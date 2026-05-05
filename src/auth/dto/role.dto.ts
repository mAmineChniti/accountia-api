import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsMongoId } from 'class-validator';
import { Role } from '@/auth/enums/role.enum';

/**
 * Request DTO for changing a user's role
 */
export class ChangeRoleDto {
  @ApiProperty({
    description: 'User ID to change role for',
    example: '507f1f77bcf86cd799439011',
  })
  @IsMongoId()
  userId: string;

  @ApiProperty({
    description: 'New role to assign to the user',
    enum: Role,
    enumName: 'Role',
    example: Role.PLATFORM_ADMIN,
  })
  @IsEnum(Role)
  newRole: Role;
}

/**
 * Response DTO after role change operation
 */
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
