import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsMongoId, IsEnum, IsOptional, IsString } from 'class-validator';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';

export class AssignBusinessUserDto {
  @ApiPropertyOptional({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsOptional()
  @IsString()
  businessId?: string;

  @ApiProperty({ example: '507f1f77bcf86cd799439011' })
  @IsMongoId()
  userId: string;

  @ApiProperty({
    enum: BusinessUserRole,
    enumName: 'BusinessUserRole',
    example: BusinessUserRole.ADMIN,
  })
  @IsEnum(BusinessUserRole)
  role: BusinessUserRole;
}

export class BusinessUserResponseDto {
  @ApiProperty({
    example: 'User assigned to business successfully',
    description: 'Success message describing the operation result',
  })
  message!: string;

  @ApiProperty({
    description: 'Business user assignment object with complete details',
    example: {
      id: '507f1f77bcf86cd799439013',
      businessId: '507f1f77bcf86cd799439011',
      userId: '507f1f77bcf86cd799439012',
      role: 'admin',
      assignedBy: '615f2e0a6c6d5c0e1a1e4a01',
      createdAt: '2024-02-17T16:30:00.000Z',
    },
  })
  businessUser!: {
    id: string;
    businessId: string;
    userId: string;
    role: string;
    assignedBy: string;
    createdAt: Date;
  };
}

export class ChangeClientRoleDto {
  @ApiPropertyOptional({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsOptional()
  @IsString()
  businessId?: string;

  @ApiProperty({
    enum: BusinessUserRole,
    enumName: 'BusinessUserRole',
    example: BusinessUserRole.ADMIN,
    description: 'New role for the client in the business',
  })
  @IsEnum(BusinessUserRole)
  role: BusinessUserRole;
}
