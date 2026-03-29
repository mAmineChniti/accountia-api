import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsMongoId, IsEnum, IsEmail, IsString, IsOptional, IsDateString } from 'class-validator';
import { BusinessUserRole } from '@/business/schemas/business-user.schema';
import { Role } from '@/auth/enums/role.enum';

export class AssignBusinessUserDto {
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
  message: string;

  @ApiProperty({
    description: 'Business user assignment object with complete details',
    example: {
      id: '507f1f77bcf86cd799439013',
      businessId: '507f1f77bcf86cd799439011',
      userId: '507f1f77bcf86cd799439012',
      role: 'admin',
      assignedBy: '615f2e0a6c6d5c0e1a1e4a01',
      isActive: true,
      createdAt: '2024-02-17T16:30:00.000Z',
    },
  })
  businessUser: {
    id: string;
    businessId: string;
    userId: string;
    role: string;
    assignedBy: string;
    isActive: boolean;
    createdAt: Date;
  };
}
export class OnboardClientDto {
  @ApiProperty({ example: 'client@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'John' })
  @IsString()
  firstName: string;

  @ApiProperty({ example: 'Doe' })
  @IsString()
  lastName: string;

  @ApiProperty({ example: '+1234567890', required: false })
  @IsString()
  @IsOptional()
  phoneNumber?: string;

  @ApiPropertyOptional({ example: 'password123', description: 'Custom password for the client' })
  @IsString()
  @IsOptional()
  password?: string;

  @ApiPropertyOptional({ example: '123 Main St, City', description: 'Billing address' })
  @IsString()
  @IsOptional()
  address?: string;

  @ApiPropertyOptional({ example: 'VAT123456789', description: 'Tax ID / VAT number' })
  @IsString()
  @IsOptional()
  vatNumber?: string;

  @ApiPropertyOptional({ example: 'FR76 1234 5678 9012 3456 7890 123', description: 'IBAN number' })
  @IsString()
  @IsOptional()
  iban?: string;
}

export class UpdateClientDto {
  @ApiPropertyOptional({ example: 'John' })
  @IsString()
  @IsOptional()
  firstName?: string;

  @ApiPropertyOptional({ example: 'Doe' })
  @IsString()
  @IsOptional()
  lastName?: string;

  @ApiPropertyOptional({ example: 'john.doe@example.com' })
  @IsEmail()
  @IsOptional()
  email?: string;

  @ApiPropertyOptional({ example: '+33123456789' })
  @IsString()
  @IsOptional()
  phoneNumber?: string;

  @ApiPropertyOptional({ example: '123 Main St, City' })
  @IsString()
  @IsOptional()
  address?: string;

  @ApiPropertyOptional({ example: 'VAT123456789' })
  @IsString()
  @IsOptional()
  vatNumber?: string;

  @ApiPropertyOptional({ example: 'FR76 1234 5678 9012 3456 7890 123' })
  @IsString()
  @IsOptional()
  iban?: string;
}
