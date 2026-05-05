import {
  IsString,
  IsOptional,
  IsEnum,
  IsNumber,
  IsBoolean,
  IsDateString,
  IsDate,
  Min,
  IsArray,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ExpenseCategory, ExpenseStatus } from '../schemas/expense.schema';

export class CreateExpenseDto {
  @ApiProperty({ description: 'Business ID for tenant resolution' })
  @IsString()
  businessId!: string;

  @ApiProperty()
  @IsString()
  title!: string;

  @ApiProperty()
  @IsNumber()
  @Min(0)
  amount!: number;

  @ApiPropertyOptional({ default: 'TND' })
  @IsOptional()
  @IsString()
  currency?: string;

  @ApiProperty({ enum: ExpenseCategory, enumName: 'ExpenseCategory' })
  @IsEnum(ExpenseCategory)
  category!: ExpenseCategory;

  @ApiProperty({ description: 'Date the expense was incurred (ISO 8601)' })
  @IsDateString()
  expenseDate!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ description: 'Vendor / merchant name' })
  @IsOptional()
  @IsString()
  vendor?: string;

  @ApiPropertyOptional({ description: 'Receipt image as base64 string' })
  @IsOptional()
  @IsString()
  receiptBase64?: string;

  @ApiPropertyOptional({ description: 'MIME type of receipt (e.g. image/png)' })
  @IsOptional()
  @IsString()
  receiptMimeType?: string;

  @ApiPropertyOptional({ default: false })
  @IsOptional()
  @IsBoolean()
  isBillable?: boolean;
}

export class UpdateExpenseDto {
  @ApiProperty({ description: 'Business ID for tenant resolution' })
  @IsString()
  businessId!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  title?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  @Min(0)
  amount?: number;

  @ApiPropertyOptional({ enum: ExpenseCategory, enumName: 'ExpenseCategory' })
  @IsOptional()
  @IsEnum(ExpenseCategory)
  category?: ExpenseCategory;

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  expenseDate?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  vendor?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  receiptBase64?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  receiptMimeType?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  isBillable?: boolean;
}

export class ReviewExpenseDto {
  @ApiProperty({ description: 'Business ID for tenant resolution' })
  @IsString()
  businessId!: string;

  @ApiProperty({
    enum: ExpenseStatus,
    enumName: 'ExpenseStatus',
  })
  @IsEnum(ExpenseStatus)
  decision!: ExpenseStatus;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  reviewNotes?: string;
}

export class ExpenseResponseDto {
  @ApiProperty()
  @IsString()
  id!: string;

  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiProperty()
  @IsString()
  submittedBy!: string;

  @ApiProperty()
  @IsString()
  submittedByName!: string;

  @ApiProperty()
  @IsString()
  title!: string;

  @ApiProperty()
  @IsNumber()
  amount!: number;

  @ApiProperty()
  @IsString()
  currency!: string;

  @ApiProperty({ enum: ExpenseCategory, enumName: 'ExpenseCategory' })
  @IsEnum(ExpenseCategory)
  category!: ExpenseCategory;

  @ApiProperty()
  @IsString()
  expenseDate!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  vendor?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  receiptBase64?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  receiptMimeType?: string;

  @ApiProperty({ enum: ExpenseStatus, enumName: 'ExpenseStatus' })
  @IsEnum(ExpenseStatus)
  status!: ExpenseStatus;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  reviewedBy?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  reviewNotes?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  reviewedAt?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  reimbursedAt?: string;

  @ApiProperty()
  @IsBoolean()
  isBillable!: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  linkedInvoiceId?: string;

  @IsDate()
  @Type(() => Date)
  createdAt!: Date;

  @IsDate()
  @Type(() => Date)
  updatedAt!: Date;
}

export class ExpenseListResponseDto {
  @ApiProperty({ type: [ExpenseResponseDto], isArray: true })
  @IsArray()
  @Type(() => ExpenseResponseDto)
  expenses!: ExpenseResponseDto[];

  @ApiProperty()
  @IsNumber()
  total!: number;

  @ApiProperty()
  @IsNumber()
  page!: number;

  @ApiProperty()
  @IsNumber()
  limit!: number;

  @ApiProperty()
  @IsNumber()
  totalPages!: number;
}

export class ExpenseSummaryDto {
  totalAmount!: number;
  byCategory!: Array<{ category: string; total: number; count: number }>;
  byStatus!: Array<{ status: string; total: number; count: number }>;
  pendingReview!: number;
  currency!: string;
}
