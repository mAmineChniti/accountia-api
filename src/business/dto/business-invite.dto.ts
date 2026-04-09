import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsEnum, IsString } from 'class-validator';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';

export class InviteBusinessUserDto {
  @ApiProperty({
    description: 'Email of the user to invite',
    example: 'user@example.com',
  })
  @IsEmail()
  invitedEmail: string;

  @ApiProperty({
    description: 'Tenant businessId to invite user to',
    type: String,
  })
  @IsString()
  businessId: string;

  @ApiProperty({
    enum: BusinessUserRole,
    enumName: 'BusinessUserRole',
    example: BusinessUserRole.MEMBER,
    description:
      'Role to assign to the invited user (OWNER, ADMIN, MEMBER, or CLIENT)',
  })
  @IsEnum(BusinessUserRole)
  businessRole: BusinessUserRole;
}

export class BusinessInviteResponseDto {
  @ApiProperty({
    example: 'Invite sent successfully',
    description: 'Success message',
  })
  message!: string;

  @ApiPropertyOptional({
    description: 'Invite details',
    example: {
      id: '507f1f77bcf86cd799439013',
      businessId: '507f1f77bcf86cd799439011',
      invitedEmail: 'user@example.com',
      inviterId: '507f1f77bcf86cd799439012',
      businessRole: 'CLIENT',
      emailSent: true,
      createdAt: '2024-02-17T16:30:00.000Z',
    },
  })
  invite?: {
    id: string;
    businessId: string;
    invitedEmail: string;
    inviterId: string;
    businessRole: BusinessUserRole;
    emailSent: boolean;
    createdAt: Date;
  };
}

export class ResendInviteDto {
  @ApiProperty({
    description: 'Invite ID to resend',
    example: '507f1f77bcf86cd799439013',
  })
  @IsString()
  inviteId: string;
}
