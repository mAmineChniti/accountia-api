import {
  IsString,
  IsOptional,
  IsEnum,
  IsDateString,
  IsNumber,
  IsArray,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum VatReportPeriod {
  MONTHLY = 'monthly',
  QUARTERLY = 'quarterly',
  YEARLY = 'yearly',
  CUSTOM = 'custom',
}

export class VatReportQueryDto {
  @ApiProperty({ description: 'Business ID for tenant resolution' })
  @IsString()
  businessId!: string;

  @ApiProperty({ enum: VatReportPeriod, description: 'Report period type' })
  @IsEnum(VatReportPeriod)
  period!: VatReportPeriod;

  @ApiPropertyOptional({
    description: 'Start date (ISO 8601) for custom range',
  })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiPropertyOptional({ description: 'End date (ISO 8601) for custom range' })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional({ description: 'Year (e.g. 2025)' })
  @IsOptional()
  @IsString()
  year?: string;

  @ApiPropertyOptional({
    description: 'Month number 1–12 (for monthly period)',
  })
  @IsOptional()
  @IsString()
  month?: string;

  @ApiPropertyOptional({
    description: 'Quarter number 1–4 (for quarterly period)',
  })
  @IsOptional()
  @IsString()
  quarter?: string;
}

export class VatLineItemDto {
  @IsString()
  productName!: string;

  @IsNumber()
  netAmount!: number;

  @IsNumber()
  vatRate!: number;

  @IsNumber()
  vatAmount!: number;

  @IsNumber()
  grossAmount!: number;
}

export class VatInvoiceDto {
  @IsString()
  invoiceId!: string;

  @IsString()
  invoiceNumber!: string;

  @IsString()
  issuedDate!: string;

  @IsString()
  recipientName!: string;

  @IsNumber()
  totalNet!: number;

  @IsNumber()
  totalVat!: number;

  @IsNumber()
  totalGross!: number;

  @IsString()
  status!: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => VatLineItemDto)
  lineItems!: VatLineItemDto[];
}

export class VatRateSummaryDto {
  @IsNumber()
  rate!: number;

  @IsNumber()
  netAmount!: number;

  @IsNumber()
  vatAmount!: number;

  @IsNumber()
  count!: number;
}

export class VatReportResponseDto {
  @IsString()
  businessId!: string;

  @IsString()
  period!: string;

  @IsString()
  startDate!: string;

  @IsString()
  endDate!: string;

  @IsNumber()
  totalOutputVat!: number;

  @IsNumber()
  totalInputVat!: number;

  @IsNumber()
  netVatPayable!: number;

  @IsNumber()
  totalTaxableRevenue!: number;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => VatRateSummaryDto)
  byRate!: VatRateSummaryDto[];

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => VatInvoiceDto)
  invoices!: VatInvoiceDto[];
}
