import {
  IsString,
  IsNumber,
  IsDate,
  IsOptional,
  IsArray,
  ValidateNested,
  IsEnum,
  Min,
  IsEmail,
} from 'class-validator';
import { Type } from 'class-transformer';
import { InvoiceRecipientType } from '@/invoices/enums/invoice-recipient.enum';

/**
 * ============================================
 * IMPORT REQUEST/RESPONSE DTOs
 * ============================================
 */

/**
 * Single line item from CSV/Excel import
 */
export class ImportInvoiceLineItemDto {
  @IsString()
  productId!: string;

  @IsString()
  productName!: string;

  @IsNumber()
  @Min(0)
  quantity!: number;

  @IsNumber()
  @Min(0)
  unitPrice!: number;

  @IsOptional()
  @IsString()
  description?: string;
}

/**
 * Single invoice record from CSV/Excel
 */
export class ImportInvoiceRecordDto {
  @IsOptional()
  @IsString()
  invoiceNumber?: string;

  /**
   * Recipient type: PLATFORM_BUSINESS, PLATFORM_INDIVIDUAL, or EXTERNAL
   */
  @IsEnum(InvoiceRecipientType)
  recipientType!: InvoiceRecipientType;

  /**
   * For PLATFORM_BUSINESS: businessId; For PLATFORM_INDIVIDUAL: userId
   * For EXTERNAL: leave empty
   */
  @IsOptional()
  @IsString()
  recipientPlatformId?: string;

  /**
   * Email address (required for PLATFORM_INDIVIDUAL and EXTERNAL)
   */
  @IsOptional()
  @IsEmail()
  recipientEmail?: string;

  /**
   * Display name (for EXTERNAL recipients)
   */
  @IsOptional()
  @IsString()
  recipientDisplayName?: string;

  /**
   * Comma-separated product IDs for simpler import format
   * Alternative to providing full line items
   */
  @IsOptional()
  @IsString()
  productIds?: string;

  /**
   * Comma-separated product names
   */
  @IsOptional()
  @IsString()
  productNames?: string;

  /**
   * Comma-separated quantities
   */
  @IsOptional()
  @IsString()
  quantities?: string;

  /**
   * Comma-separated unit prices
   */
  @IsOptional()
  @IsString()
  unitPrices?: string;

  /**
   * Or provide as JSON string for complex imports
   */
  @IsOptional()
  @IsString()
  lineItemsJson?: string;

  @IsDate()
  @Type(() => Date)
  issuedDate!: Date;

  @IsDate()
  @Type(() => Date)
  dueDate!: Date;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  paymentTerms?: string;

  @IsOptional()
  @IsString()
  currency?: string;
}

/**
 * File import request
 */
export class ImportInvoicesFromFileDto {
  /**
   * Only for multipart form data - file is handled separately
   * This is a placeholder DTO for Swagger documentation
   */
  @IsString()
  @IsOptional()
  fileDescription?: string;
}

/**
 * Result of importing a single invoice
 */
export class ImportedInvoiceResultDto {
  @IsOptional()
  @IsString()
  invoiceNumber?: string;

  @IsOptional()
  @IsString()
  invoiceId?: string;

  @IsString()
  status!: 'success' | 'error' | 'warning';

  @IsOptional()
  @IsString()
  message?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  warnings?: string[];

  @IsOptional()
  @IsNumber()
  lineItemsCount?: number;

  @IsOptional()
  @IsNumber()
  totalAmount?: number;
}

/**
 * Bulk import response with summary statistics
 */
export class BulkImportInvoicesResponseDto {
  @IsNumber()
  @Min(0)
  totalRecords!: number;

  @IsNumber()
  @Min(0)
  successCount!: number;

  @IsNumber()
  @Min(0)
  failedCount!: number;

  @IsNumber()
  @Min(0)
  warningCount!: number;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ImportedInvoiceResultDto)
  results!: ImportedInvoiceResultDto[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  generalErrors?: string[];

  @IsOptional()
  @IsString()
  importStartedAt!: string;

  @IsOptional()
  @IsString()
  importCompletedAt!: string;

  @IsOptional()
  @IsNumber()
  processingTimeMs?: number;
}

/**
 * Template/example for CSV import
 */
export class ImportTemplateResponseDto {
  @IsString()
  csvExample!: string;

  @IsArray()
  @IsString({ each: true })
  csvColumns!: string[];

  @IsArray()
  @IsString({ each: true })
  recipientTypes!: string[];

  @IsString()
  notes!: string;
}
