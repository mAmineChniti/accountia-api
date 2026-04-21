import { IsString, IsDate, IsOptional } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type, Transform } from 'class-transformer';

export class CreateAccountingJobDto {
  @ApiPropertyOptional({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsOptional()
  @IsString()
  @Transform(
    ({ value, obj }: { value: unknown; obj: Record<string, unknown> }) => {
      return value ?? obj?.business_id ?? obj?.businessId;
    }
  )
  businessId?: string;

  @ApiProperty({
    description: 'Period start date (ISO 8601)',
    type: String,
    format: 'date-time',
  })
  @IsDate()
  @Transform(
    ({ value, obj }: { value: unknown; obj: Record<string, unknown> }) => {
      const raw = value ?? obj?.period_start ?? obj?.periodStart;
      return raw ? new Date(raw as string) : raw;
    }
  )
  @Type(() => Date)
  periodStart!: Date;

  @ApiProperty({
    description: 'Period end date (ISO 8601)',
    type: String,
    format: 'date-time',
  })
  @IsDate()
  @Transform(
    ({ value, obj }: { value: unknown; obj: Record<string, unknown> }) => {
      const raw = value ?? obj?.period_end ?? obj?.periodEnd;
      return raw ? new Date(raw as string) : raw;
    }
  )
  @Type(() => Date)
  periodEnd!: Date;
}

export interface InternalCreateAccountingJobPayload {
  business_id: string;
  period_start: string;
  period_end: string;
}
