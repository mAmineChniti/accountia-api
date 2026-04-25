import { IsString, IsDate, IsOptional, IsNotEmpty } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class CreateAccountingJobDto {
  @ApiPropertyOptional({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  businessId?: string;

  @ApiProperty({
    description: 'Period start date (ISO 8601)',
    type: String,
    format: 'date-time',
  })
  @IsDate()
  @Type(() => Date)
  periodStart!: Date;

  @ApiProperty({
    description: 'Period end date (ISO 8601)',
    type: String,
    format: 'date-time',
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
