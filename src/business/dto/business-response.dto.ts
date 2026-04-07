import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class BusinessResponseDto {
  @ApiProperty({
    example: 'Business retrieved successfully',
    description: 'Success message describing the operation result',
  })
  message!: string;

  @ApiProperty({
    description: 'Business object with complete details',
    example: {
      id: '507f1f77bcf86cd799439011',
      name: 'Tech Solutions Inc.',
      description: 'A technology company specializing in software development',
      website: 'https://techsolutions.com',
      phone: '+1-555-0123',
      email: 'contact@techsolutions.com',
      databaseName: 'tech_solutions_inc_1708198200000',
      status: 'approved',
      createdAt: '2024-02-17T16:30:00.000Z',
      updatedAt: '2024-02-17T16:30:00.000Z',
    },
  })
  business!: {
    id: string;
    name: string;
    description: string;
    website?: string;
    phone: string;
    email: string;
    databaseName: string;
    status: string;
    createdAt: Date;
    updatedAt: Date;
  };
}

export class BusinessesListResponseDto {
  @ApiProperty({
    example: 'Businesses retrieved successfully',
    description: 'Success message describing the operation result',
  })
  message!: string;

  @ApiProperty({
    description: 'Array of businesses with basic details',
    type: [Object],
    isArray: true,
    example: [
      {
        id: '507f1f77bcf86cd799439011',
        name: 'Tech Solutions Inc.',
        phone: '+1-555-0123',
        status: 'approved',
        createdAt: '2024-02-17T16:30:00.000Z',
      },
    ],
  })
  businesses!: {
    id: string;
    name: string;
    phone: string;
    status: string;
    createdAt: Date;
    membershipRole?: string;
  }[];
}

export class BusinessApplicationListResponseDto {
  @ApiProperty({
    example: 'Business applications retrieved successfully',
    description: 'Success message describing the operation result',
  })
  message!: string;

  @ApiProperty({
    description: 'Array of business applications with details',
    type: [Object],
    isArray: true,
    example: [
      {
        id: '507f1f77bcf86cd799439011',
        businessName: 'Tech Solutions Inc.',
        description:
          'A technology company specializing in software development',
        website: 'https://techsolutions.com',
        phone: '+1-555-0123',
        applicantId: '615f2e0a6c6d5c0e1a1e4a01',
        applicantEmail: 'john@example.com',
        applicantName: 'John Doe',
        status: 'pending',
        createdAt: '2024-02-17T16:30:00.000Z',
      },
    ],
  })
  applications!: {
    id: string;
    businessName: string;
    description: string;
    website?: string;
    phone: string;
    applicantId: string;
    applicantEmail?: string;
    applicantName?: string;
    status: string;
    createdAt: Date;
  }[];
}

export class InviteTeamMemberResponseDto {
  @ApiProperty({
    example: 'Invitation sent successfully',
    description: 'Result message',
  })
  message!: string;

  @ApiProperty({
    example: '67f31f77bcf86cd7994390aa',
    description: 'Created invitation id',
  })
  inviteId!: string;

  @ApiProperty({
    example: '2026-04-13T10:00:00.000Z',
    description: 'Invitation expiration date',
  })
  expiresAt!: Date;
}

export class AcceptInviteResponseDto {
  @ApiProperty({
    example: 'Invitation accepted successfully',
    description: 'Result message',
  })
  message!: string;

  @ApiProperty({
    example: 'admin@company.tn',
    description: 'Email tied to the accepted invitation',
  })
  email!: string;
}

export class InvitationPreviewResponseDto {
  @ApiProperty({
    example: 'admin@company.tn',
    description: 'Invited email address',
  })
  email!: string;

  @ApiProperty({
    example: 'Evenix',
    description: 'Business display name',
  })
  businessName!: string;

  @ApiProperty({
    example: 'PENDING',
    enum: ['PENDING', 'ACCEPTED', 'CANCELLED', 'EXPIRED'],
    description: 'Invitation status',
  })
  status!: 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';

  @ApiProperty({
    example: '2026-04-13T10:00:00.000Z',
    description: 'Invitation expiration date',
  })
  expiresAt!: Date;
}

export class TeamMemberItemResponseDto {
  @ApiProperty({ example: '67f31f77bcf86cd7994390aa' })
  id!: string;

  @ApiPropertyOptional({ example: '67f31f77bcf86cd7994390ab' })
  userId?: string;

  @ApiPropertyOptional({ example: 'Rachid' })
  firstName?: string;

  @ApiPropertyOptional({ example: 'Ben Salah' })
  lastName?: string;

  @ApiProperty({ example: 'admin@company.tn' })
  email!: string;

  @ApiProperty({ example: 'ADMIN' })
  role!: string;

  @ApiProperty({ example: 'ACCEPTED' })
  status!: 'ACCEPTED' | 'PENDING';

  @ApiProperty({ example: '2026-04-06T12:00:00.000Z' })
  createdAt!: Date;

  @ApiPropertyOptional({
    example: '2026-04-13T10:00:00.000Z',
  })
  expiresAt?: Date;
}

export class BusinessTeamResponseDto {
  @ApiProperty({
    example: 'Team members retrieved successfully',
    description: 'Result message',
  })
  message!: string;

  @ApiProperty({ type: TeamMemberItemResponseDto, isArray: true })
  members!: TeamMemberItemResponseDto[];
}

export class CancelInviteResponseDto {
  @ApiProperty({
    example: 'Invitation cancelled successfully',
    description: 'Result message',
  })
  message!: string;
}
