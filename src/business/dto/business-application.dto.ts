import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsDefined,
  IsIn,
  MinLength,
  MaxLength,
  IsEmail,
} from 'class-validator';

export class CreateBusinessApplicationDto {
  @ApiProperty({ example: 'Tech Solutions Inc.' })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  businessName: string;

  @ApiProperty({
    example: 'A technology company specializing in software development',
  })
  @IsString()
  @MinLength(10)
  @MaxLength(500)
  description: string;

  @ApiPropertyOptional({ example: 'https://techsolutions.com' })
  @IsOptional()
  @IsString()
  website?: string;

  @ApiProperty({ example: '+1-555-0123' })
  @IsDefined()
  @IsString()
  phone: string;

  @ApiProperty({ example: 'contact@techsolutions.com' })
  @IsEmail()
  businessEmail: string;
}

export class ReviewBusinessApplicationDto {
  @ApiProperty({
    enum: ['approved', 'rejected'],
    enumName: 'ApplicationStatus',
    example: 'approved',
  })
  @IsDefined()
  @IsIn(['approved', 'rejected'])
  status: 'approved' | 'rejected';

  @ApiPropertyOptional({
    example: 'Application approved - business meets all requirements',
  })
  @IsOptional()
  @IsString()
  reviewNotes?: string;
}

export class BusinessApplicationResponseDto {
  @ApiProperty({
    example: 'Business application submitted successfully',
    description: 'Success message describing the operation result',
  })
  message!: string;

  @ApiProperty({
    description: 'Business application object with complete details',
    example: {
      id: '507f1f77bcf86cd799439011',
      businessName: 'Tech Solutions Inc.',
      description: 'A technology company specializing in software development',
      website: 'https://techsolutions.com',
      phone: '+1-555-0123',
      businessEmail: 'contact@techsolutions.com',
      applicantId: '615f2e0a6c6d5c0e1a1e4a01',
      applicantEmail: 'john@example.com',
      applicantName: 'John Doe',
      status: 'pending',
      createdAt: '2024-02-17T16:30:00.000Z',
    },
  })
  application!: {
    id: string;
    businessName: string;
    description: string;
    website?: string;
    phone: string;
    businessEmail: string;
    applicantId: string;
    applicantEmail?: string;
    applicantName?: string;
    status: string;
    createdAt: Date;
    reviewedAt?: Date;
  };
}
