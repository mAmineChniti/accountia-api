import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsMongoId } from 'class-validator';
import { Role } from '@/auth/enums/role.enum';

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
