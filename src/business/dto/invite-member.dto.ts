import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsIn, IsNotEmpty, IsOptional } from 'class-validator';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';

enum InviteMemberAllowedRole {
  ADMIN = BusinessUserRole.ADMIN,
}

export class InviteMemberDto {
  @ApiProperty({ description: 'Email address of the user to invite' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'Role to assign to the invited user (only ADMIN is allowed)',
    enum: InviteMemberAllowedRole,
    enumName: 'InviteMemberAllowedRole',
  })
  @IsIn([BusinessUserRole.ADMIN])
  @IsNotEmpty()
  role: BusinessUserRole;

  @ApiPropertyOptional({
    description: 'Locale used to build invitation link',
    enum: ['en', 'fr', 'ar'],
  })
  @IsOptional()
  @IsIn(['en', 'fr', 'ar'])
  lang?: 'en' | 'fr' | 'ar';
}
