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

  @ApiProperty({ enum: ExpenseCategory })
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

  @ApiPropertyOptional({ enum: ExpenseCategory })
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

  @ApiProperty({ enum: [ExpenseStatus.APPROVED, ExpenseStatus.REJECTED] })
  @IsEnum(ExpenseStatus)
  decision!: ExpenseStatus.APPROVED | ExpenseStatus.REJECTED;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  reviewNotes?: string;
}

export class ExpenseResponseDto {
  id!: string;
  businessId!: string;
  submittedBy!: string;
  submittedByName!: string;
  title!: string;
  amount!: number;
  currency!: string;
  category!: ExpenseCategory;
  expenseDate!: string;
  description?: string;
  vendor?: string;
  receiptBase64?: string;
  receiptMimeType?: string;
  status!: ExpenseStatus;
  reviewedBy?: string;
  reviewNotes?: string;
  reviewedAt?: string;
  reimbursedAt?: string;
  isBillable!: boolean;
  linkedInvoiceId?: string;

  @IsDate()
  @Type(() => Date)
  createdAt!: Date;

  @IsDate()
  @Type(() => Date)
  updatedAt!: Date;
}

export class ExpenseListResponseDto {
  @IsArray()
  expenses!: ExpenseResponseDto[];

  total!: number;
  page!: number;
  limit!: number;
  totalPages!: number;
}

export class ExpenseSummaryDto {
  totalAmount!: number;
  byCategory!: Array<{ category: string; total: number; count: number }>;
  byStatus!: Array<{ status: string; total: number; count: number }>;
  pendingReview!: number;
  currency!: string;
}
