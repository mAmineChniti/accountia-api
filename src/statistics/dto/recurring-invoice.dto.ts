import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsNumber,
  IsEnum,
  IsDateString,
  IsOptional,
  IsArray,
  ValidateNested,
  IsBoolean,
} from 'class-validator';
import { Type } from 'class-transformer';
import { RecurringFrequency, RecurringStatus } from '../schemas/recurring-invoice.schema';

export class InvoiceItemDto {
  @ApiProperty({ example: 'Consulting Services' })
  @IsString()
  description: string;

  @ApiProperty({ example: 1 })
  @IsNumber()
  quantity: number;

  @ApiProperty({ example: 1500 })
  @IsNumber()
  price: number;
}

export class CreateRecurringInvoiceDto {
  @ApiProperty({ example: 'client123' })
  @IsString()
  clientId: string;

  @ApiProperty({ example: 'Acme Corp' })
  @IsString()
  clientName: string;

  @ApiPropertyOptional({ example: 'billing@acme.com' })
  @IsOptional()
  @IsString()
  clientEmail?: string;

  @ApiProperty({ type: [InvoiceItemDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InvoiceItemDto)
  items: InvoiceItemDto[];

  @ApiProperty({ example: 1500 })
  @IsNumber()
  totalAmount: number;

  @ApiProperty({ enum: RecurringFrequency })
  @IsEnum(RecurringFrequency)
  frequency: RecurringFrequency;

  @ApiProperty({ example: 'template123' })
  @IsString()
  templateId: string;

  @ApiProperty({ example: '2026-04-01T00:00:00Z' })
  @IsDateString()
  startDate: string;

  @ApiPropertyOptional({ example: '2027-04-01T00:00:00Z' })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  autoSend?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  generateFirstImmediately?: boolean;
}

export class UpdateRecurringInvoiceStatusDto {
  @ApiProperty({ enum: RecurringStatus })
  @IsEnum(RecurringStatus)
  status: RecurringStatus;
}
