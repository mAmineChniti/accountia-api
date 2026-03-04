import { ApiProperty } from '@nestjs/swagger';

export class BusinessResponseDto {
  @ApiProperty({
    example: 'Business retrieved successfully',
    description: 'Success message describing the operation result',
  })
  message: string;

  @ApiProperty({
    description: 'Business object with complete details',
    example: {
      id: '507f1f77bcf86cd799439011',
      name: 'Tech Solutions Inc.',
      description: 'A technology company specializing in software development',
      website: 'https://techsolutions.com',
      phone: '+1-555-0123',
      databaseName: 'tech_solutions_inc_1708198200000',
      status: 'approved',
      isActive: true,
      logo: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...',
      tags: ['technology', 'software'],
      createdAt: '2024-02-17T16:30:00.000Z',
      updatedAt: '2024-02-17T16:30:00.000Z',
    },
  })
  business: {
    id: string;
    name: string;
    description: string;
    website?: string;
    phone: string;
    databaseName: string;
    status: string;
    isActive: boolean;
    logo?: string;
    tags: string[];
    createdAt: Date;
    updatedAt: Date;
  };
}

export class BusinessesListResponseDto {
  @ApiProperty({
    example: 'Businesses retrieved successfully',
    description: 'Success message describing the operation result',
  })
  message: string;

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
        isActive: true,
        createdAt: '2024-02-17T16:30:00.000Z',
      },
    ],
  })
  businesses: {
    id: string;
    name: string;
    phone: string;
    status: string;
    isActive: boolean;
    createdAt: Date;
  }[];
}

export class BusinessApplicationListResponseDto {
  @ApiProperty({
    example: 'Business applications retrieved successfully',
    description: 'Success message describing the operation result',
  })
  message: string;

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
        status: 'pending',
        createdAt: '2024-02-17T16:30:00.000Z',
      },
    ],
  })
  applications: {
    id: string;
    businessName: string;
    description: string;
    website?: string;
    phone: string;
    applicantId: string;
    status: string;
    createdAt: Date;
  }[];
}
