import {
  IsString,
  IsOptional,
  IsEnum,
  IsNumber,
  IsBoolean,
  IsDateString,
  IsArray,
  ValidateNested,
  Min,
  IsObject,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  RecurringFrequency,
  RecurringStatus,
  RecurringEndCondition,
} from '../schemas/recurring-invoice.schema';

export class RecurringLineItemDto {
  @ApiPropertyOptional()
  @IsOptional()
  productId?: string;

  @ApiProperty()
  @IsString()
  productName!: string;

  @ApiProperty()
  @IsNumber()
  @Min(1)
  quantity!: number;

  @ApiProperty()
  @IsNumber()
  @Min(0)
  unitPrice!: number;

  @ApiProperty()
  @IsNumber()
  @Min(0)
  amount!: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;
}

export class CreateRecurringInvoiceDto {
  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiProperty()
  @IsString()
  name!: string;

  @ApiProperty({ enum: RecurringFrequency })
  @IsEnum(RecurringFrequency)
  frequency!: RecurringFrequency;

  @ApiProperty({ description: 'ISO 8601 start date' })
  @IsDateString()
  startDate!: string;

  @ApiProperty({ enum: RecurringEndCondition })
  @IsEnum(RecurringEndCondition)
  endCondition!: RecurringEndCondition;

  @ApiPropertyOptional({ description: 'Max number of generations (for AFTER_OCCURRENCES)' })
  @IsOptional()
  @IsNumber()
  @Min(1)
  maxOccurrences?: number;

  @ApiPropertyOptional({ description: 'End date (ISO 8601) for BY_DATE condition' })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiProperty({ type: [RecurringLineItemDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RecurringLineItemDto)
  lineItems!: RecurringLineItemDto[];

  @ApiProperty({ description: 'Total invoice amount' })
  @IsNumber()
  @Min(0)
  totalAmount!: number;

  @ApiPropertyOptional({ default: 'TND' })
  @IsOptional()
  @IsString()
  currency?: string;

  @ApiPropertyOptional({ default: 30, description: 'Days from issue date until due' })
  @IsOptional()
  @IsNumber()
  @Min(0)
  dueDaysFromIssue?: number;

  @ApiProperty({ description: 'Recipient object (same shape as invoice recipient)' })
  @IsObject()
  recipient!: Record<string, unknown>;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  paymentTerms?: string;

  @ApiPropertyOptional({ default: false, description: 'Auto-issue generated invoices' })
  @IsOptional()
  @IsBoolean()
  autoIssue?: boolean;
}

export class UpdateRecurringInvoiceDto {
  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ enum: RecurringStatus })
  @IsOptional()
  @IsEnum(RecurringStatus)
  status?: RecurringStatus;

  @ApiPropertyOptional({ enum: RecurringEndCondition })
  @IsOptional()
  @IsEnum(RecurringEndCondition)
  endCondition?: RecurringEndCondition;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  maxOccurrences?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  autoIssue?: boolean;
}

export class RecurringInvoiceResponseDto {
  id!: string;
  businessId!: string;
  name!: string;
  frequency!: RecurringFrequency;
  status!: RecurringStatus;
  startDate!: string;
  endCondition!: RecurringEndCondition;
  maxOccurrences?: number;
  occurrenceCount!: number;
  endDate?: string;
  nextRunAt!: string;
  lastRunAt?: string;
  lineItems!: RecurringLineItemDto[];
  totalAmount!: number;
  currency!: string;
  dueDaysFromIssue!: number;
  recipient!: Record<string, unknown>;
  description?: string;
  paymentTerms?: string;
  autoIssue!: boolean;
  generatedInvoiceIds!: string[];
  createdBy?: string;
  createdAt!: Date;
  updatedAt!: Date;
}

export class RecurringInvoiceListResponseDto {
  schedules!: RecurringInvoiceResponseDto[];
  total!: number;
  page!: number;
  limit!: number;
  totalPages!: number;
}
