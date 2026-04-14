import {
  IsString,
  IsNumber,
  IsDate,
  IsOptional,
  IsArray,
  ValidateNested,
  IsEnum,
  Min,
  IsBoolean,
  MinLength,
  Matches,
} from 'class-validator';
import { ApiPropertyOptional, ApiProperty } from '@nestjs/swagger';
import { Type, Transform } from 'class-transformer';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import {
  InvoiceRecipientType,
  RecipientResolutionStatus,
} from '@/invoices/enums/invoice-recipient.enum';

/**
 * Helper to convert MongoDB ObjectId to string
 */
const ObjectIdToString = () =>
  Transform(({ value }: { value: unknown }) => {
    if (typeof value === 'string') return value;
    if (value && typeof value === 'object' && 'toString' in value) {
      return (value as { toString(): string }).toString();
    }
    return value;
  });

/**
 * Helper to convert MongoDB _id to id
 */
const TransformId = () =>
  Transform(({ obj }: { obj: Record<string, unknown> }) => {
    const id = obj._id ?? obj.id;
    if (typeof id === 'string') return id;
    if (id && typeof id === 'object' && 'toString' in id) {
      return (id as { toString(): string }).toString();
    }
    return id;
  });

/**
 * ============================================
 * REQUEST DTOs (Input/Creation)
 * ============================================
 */

export class CreateInvoiceLineItemDto {
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
 * Recipient can be a platform business, platform individual, or external contact
 */
export class CreateInvoiceRecipientDto {
  @IsEnum(InvoiceRecipientType)
  type!: InvoiceRecipientType;

  /**
   * For PLATFORM_BUSINESS: businessId
   * For PLATFORM_INDIVIDUAL: userId
   * For EXTERNAL: leave undefined
   */
  @IsOptional()
  @IsString()
  platformId?: string;

  /**
   * Email address of recipient (for individual or external)
   */
  @IsOptional()
  @IsString()
  email?: string;

  /**
   * Display name (for external recipients)
   */
  @IsOptional()
  @IsString()
  displayName?: string;
}

export class CreateInvoiceDto {
  @ApiPropertyOptional({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsOptional()
  @IsString()
  businessId?: string;

  @IsOptional()
  @IsString()
  invoiceNumber?: string;

  @ValidateNested()
  @Type(() => CreateInvoiceRecipientDto)
  recipient!: CreateInvoiceRecipientDto;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateInvoiceLineItemDto)
  lineItems!: CreateInvoiceLineItemDto[];

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

export class UpdateInvoiceDto {
  @ApiPropertyOptional({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsOptional()
  @IsString()
  businessId?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  paymentTerms?: string;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  dueDate?: Date;
}

/**
 * Change invoice state (issue, void, mark paid, etc.)
 */
export class TransitionInvoiceStateDto {
  @ApiPropertyOptional({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsOptional()
  @IsString()
  businessId?: string;

  @IsEnum(InvoiceStatus)
  newStatus!: InvoiceStatus;

  @IsOptional()
  @IsString()
  reason?: string;

  /**
   * For PAID/PARTIAL transitions: amount paid
   */
  @IsOptional()
  @IsNumber()
  @Min(0)
  amountPaid?: number;
}

/**
 * ============================================
 * RESPONSE DTOs (Output)
 * ============================================
 */

export class InvoiceLineItemResponseDto {
  @TransformId()
  @IsString()
  id!: string;
  @IsString()
  productId!: string;
  @IsString()
  productName!: string;
  @IsNumber()
  quantity!: number;
  @IsNumber()
  unitPrice!: number;
  @IsNumber()
  amount!: number;

  @IsOptional()
  @IsString()
  description?: string;
}

export class InvoiceRecipientResponseDto {
  @IsEnum(InvoiceRecipientType)
  type!: InvoiceRecipientType;

  @IsOptional()
  @ObjectIdToString()
  @IsString()
  platformId?: string;

  @IsOptional()
  @IsString()
  tenantDatabaseName?: string;

  @IsOptional()
  @IsString()
  email?: string;

  @IsOptional()
  @IsString()
  displayName?: string;

  @IsEnum(RecipientResolutionStatus)
  resolutionStatus!: RecipientResolutionStatus;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  lastResolutionAttempt?: Date;
}

export class InvoiceResponseDto {
  @TransformId()
  @IsString()
  id!: string;

  @ObjectIdToString()
  @IsString()
  issuerBusinessId!: string;
  @IsString()
  invoiceNumber!: string;

  @ValidateNested()
  @Type(() => InvoiceRecipientResponseDto)
  recipient!: InvoiceRecipientResponseDto;
  @IsEnum(InvoiceStatus)
  status!: InvoiceStatus;

  @IsNumber()
  totalAmount!: number;
  @IsString()
  currency!: string;
  @IsNumber()
  amountPaid!: number;

  @IsDate()
  @Type(() => Date)
  issuedDate!: Date;
  @IsDate()
  @Type(() => Date)
  dueDate!: Date;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InvoiceLineItemResponseDto)
  lineItems!: InvoiceLineItemResponseDto[];

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  paymentTerms?: string;

  @IsOptional()
  @IsString()
  voidReason?: string;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  voidedAt?: Date;

  @IsOptional()
  @ObjectIdToString()
  @IsString()
  createdBy?: string;

  @IsOptional()
  @ObjectIdToString()
  @IsString()
  lastModifiedBy?: string;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  lastStatusChangeAt?: Date;

  @IsDate()
  @Type(() => Date)
  createdAt!: Date;
  @IsDate()
  @Type(() => Date)
  updatedAt!: Date;
}

/**
 * For recipient view - simplified, read-only
 */
export class InvoiceReceiptResponseDto {
  @TransformId()
  @IsString()
  id!: string;

  @ObjectIdToString()
  @IsString()
  invoiceId!: string;
  @IsString()
  issuerTenantDatabaseName!: string;
  @ObjectIdToString()
  @IsString()
  issuerBusinessId!: string;
  @IsString()
  issuerBusinessName!: string;

  @IsString()
  invoiceNumber!: string;
  @IsNumber()
  totalAmount!: number;
  @IsString()
  currency!: string;

  @IsDate()
  @Type(() => Date)
  issuedDate!: Date;
  @IsDate()
  @Type(() => Date)
  dueDate!: Date;

  @IsEnum(InvoiceStatus)
  invoiceStatus!: InvoiceStatus;
  @IsBoolean()
  recipientViewed!: boolean;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  recipientViewedAt?: Date;

  @IsDate()
  @Type(() => Date)
  lastSyncedAt!: Date;
  @IsDate()
  @Type(() => Date)
  createdAt!: Date;
}

/**
 * List response with pagination
 *
 * - total: Actual count of ALL invoices for the business (unfiltered)
 * - filteredTotal: Count of invoices matching the applied filters
 * - totalPages: Pagination based on filtered results
 *
 * This allows clients to show: "Showing X of Y total invoices (with Z matching your filter)"
 */
export class InvoiceListResponseDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InvoiceResponseDto)
  invoices!: InvoiceResponseDto[];

  @IsNumber()
  @ApiProperty({
    description:
      'Actual total count of ALL invoices for this business (unfiltered)',
    example: 15,
  })
  total!: number;

  @IsNumber()
  @ApiProperty({
    description: 'Count of invoices matching the applied filters',
    example: 5,
  })
  filteredTotal!: number;

  @IsNumber()
  page!: number;

  @IsNumber()
  limit!: number;

  @IsNumber()
  totalPages!: number;
}

export class InvoiceReceiptListResponseDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InvoiceReceiptResponseDto)
  receipts!: InvoiceReceiptResponseDto[];

  @IsNumber()
  @ApiProperty({
    description: 'Actual total count of ALL invoices received (unfiltered)',
    example: 12,
  })
  total!: number;

  @IsNumber()
  @ApiProperty({
    description: 'Count of invoices matching the applied filters',
    example: 4,
  })
  filteredTotal!: number;

  @IsNumber()
  page!: number;

  @IsNumber()
  limit!: number;

  @IsNumber()
  totalPages!: number;
}

export class CreateInvoiceCheckoutSessionDto {}

export class MockInvoicePaymentDto {
  @IsString()
  @MinLength(2)
  cardholderName!: string;

  @IsString()
  @Matches(/^\d{4}(?:\s\d{4}){3}$/)
  cardNumber!: string;

  @IsString()
  @Matches(/^(0[1-9]|1[0-2])\/\d{2}$/)
  expiry!: string;

  @IsString()
  @Matches(/^\d{3,4}$/)
  cvc!: string;
}

export class InvoiceCheckoutSessionResponseDto {
  @IsString()
  clientSecret!: string;

  @IsString()
  sessionId!: string;

  @IsOptional()
  @IsString()
  checkoutUrl?: string;
}
