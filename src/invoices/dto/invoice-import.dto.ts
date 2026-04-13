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
  IsIn,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';
import { Type } from 'class-transformer';
import { InvoiceRecipientType } from '@/invoices/enums/invoice-recipient.enum';

/**
 * ============================================
 * CUSTOM VALIDATORS
 * ============================================
 */

/**
 * Validator to ensure at least one line-item source is provided
 */
@ValidatorConstraint({ name: 'HasLineItemSource', async: false })
export class HasLineItemSourceValidator implements ValidatorConstraintInterface {
  validate(value: unknown, _args: ValidationArguments): boolean {
    const object = _args.object as Record<string, unknown>;
    const { productIds, quantities, unitPrices, lineItemsJson } = object;

    // At least one of these should be a non-empty string
    const hasProductIds =
      productIds &&
      typeof productIds === 'string' &&
      productIds.trim().length > 0;
    const hasQuantities =
      quantities &&
      typeof quantities === 'string' &&
      quantities.trim().length > 0;
    const hasUnitPrices =
      unitPrices &&
      typeof unitPrices === 'string' &&
      unitPrices.trim().length > 0;
    const hasLineItemsJson =
      lineItemsJson &&
      typeof lineItemsJson === 'string' &&
      lineItemsJson.trim().length > 0;

    return !!(
      // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
      (hasLineItemsJson || (hasProductIds && hasQuantities && hasUnitPrices))
    );
  }

  defaultMessage(_args: ValidationArguments) {
    return 'Provide lineItemsJson or comma/pipe-separated product fields (productIds, quantities, unitPrices)';
  }
}

/**
 * Validator to ensure recipient fields match the recipient type
 */
@ValidatorConstraint({ name: 'ValidateRecipientType', async: false })
export class ValidateRecipientTypeValidator implements ValidatorConstraintInterface {
  validate(value: unknown, _args: ValidationArguments): boolean {
    const object = _args.object as Record<string, unknown>;
    const {
      recipientType,
      recipientPlatformId,
      recipientEmail,
      recipientDisplayName,
    } = object;

    if (!recipientType) return false;

    const type = recipientType as InvoiceRecipientType;

    if (type === InvoiceRecipientType.PLATFORM_BUSINESS) {
      // Requires recipientPlatformId
      return !!(
        recipientPlatformId &&
        typeof recipientPlatformId === 'string' &&
        recipientPlatformId.trim().length > 0
      );
    }

    if (type === InvoiceRecipientType.PLATFORM_INDIVIDUAL) {
      // Requires recipientPlatformId and recipientEmail
      const hasPlatformId =
        recipientPlatformId &&
        typeof recipientPlatformId === 'string' &&
        recipientPlatformId.trim().length > 0;
      const hasEmail =
        recipientEmail &&
        typeof recipientEmail === 'string' &&
        recipientEmail.trim().length > 0;
      return !!(hasPlatformId && hasEmail);
    }

    if (type === InvoiceRecipientType.EXTERNAL) {
      // Requires recipientEmail and recipientDisplayName, recipientPlatformId should be absent/empty
      const hasEmail =
        recipientEmail &&
        typeof recipientEmail === 'string' &&
        recipientEmail.trim().length > 0;
      const hasDisplayName =
        recipientDisplayName &&
        typeof recipientDisplayName === 'string' &&
        recipientDisplayName.trim().length > 0;
      const noPlatformId =
        !recipientPlatformId ||
        (typeof recipientPlatformId === 'string' &&
          recipientPlatformId.trim().length === 0);
      return !!(hasEmail && hasDisplayName && noPlatformId);
    }

    return false;
  }

  defaultMessage(args: ValidationArguments) {
    const object = args.object as Record<string, unknown>;
    const type = object.recipientType as InvoiceRecipientType;

    if (type === InvoiceRecipientType.PLATFORM_BUSINESS) {
      return 'PLATFORM_BUSINESS requires recipientPlatformId';
    }
    if (type === InvoiceRecipientType.PLATFORM_INDIVIDUAL) {
      return 'PLATFORM_INDIVIDUAL requires recipientPlatformId and recipientEmail';
    }
    if (type === InvoiceRecipientType.EXTERNAL) {
      return 'EXTERNAL requires recipientEmail and recipientDisplayName, and recipientPlatformId should be absent/empty';
    }

    return 'Invalid recipient type configuration';
  }
}

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
  @IsNumber()
  itemNumber?: number;

  @IsOptional()
  @IsString()
  invoiceNumber?: string;

  @IsOptional()
  @IsString()
  invoiceId?: string;

  @IsOptional()
  success?: boolean;

  @IsString()
  @IsIn(['success', 'error', 'warning'])
  status!: 'success' | 'error' | 'warning';

  @IsOptional()
  @IsString()
  message?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  errors?: string[];

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
  @IsEnum(InvoiceRecipientType, { each: true })
  recipientTypes!: InvoiceRecipientType[];

  @IsString()
  notes!: string;
}
