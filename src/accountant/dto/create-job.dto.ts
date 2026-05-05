import { IsString, IsDate, IsOptional, Matches } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class CreateAccountingJobDto {
  @ApiPropertyOptional({
    description:
      'Tenant businessId used to resolve current business context (MongoDB ObjectId).',
    type: String,
    example: '60d5f4832f8fb814c8a1b234',
  })
  @IsOptional()
  @IsString()
  @Matches(/^[\dA-Fa-f]{24}$/, {
    message: 'businessId must be a 24 character hex MongoDB ObjectId',
  })
  businessId?: string;

  @ApiProperty({
    description: 'Period start date (ISO 8601)',
    type: String,
    format: 'date-time',
    example: '2024-01-01T00:00:00Z',
  })
  @IsDate()
  @Type(() => Date)
  periodStart!: Date;

  @ApiProperty({
    description: 'Period end date (ISO 8601)',
    type: String,
    format: 'date-time',
    example: '2024-01-31T23:59:59Z',
  })
  @IsDate()
  @Type(() => Date)
  periodEnd!: Date;
}

export interface InternalCreateAccountingJobPayload {
  businessId: string;
  periodStart: string;
  periodEnd: string;
}
