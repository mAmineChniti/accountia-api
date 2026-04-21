/* eslint-disable unicorn/no-abusive-eslint-disable */
/* eslint-disable */
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import {
  InvoiceRecipientType,
  RecipientResolutionStatus,
} from '@/invoices/enums/invoice-recipient.enum';

/**
 * InvoiceLineItem - Subdocument representing a single line on the invoice
 */
@Schema({ _id: true })
export class InvoiceLineItem extends Document {
  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'Product' })
  productId!: string;

  @Prop({ required: true })
  productName!: string;

  @Prop({ required: true, type: Number })
  quantity!: number;

  @Prop({ required: true, type: Number })
  unitPrice!: number;

  @Prop({ required: true, type: Number })
  amount!: number; // quantity * unitPrice

  @Prop({ type: String })
  description?: string;

  createdAt!: Date; // Auto added by Mongoose
}

export const InvoiceLineItemSchema =
  SchemaFactory.createForClass(InvoiceLineItem);

/**
 * InvoiceRecipient - Flexible recipient model supporting multiple types
 * Can be a platform business, platform individual, or external contact
 */
@Schema({ _id: false })
export class InvoiceRecipient {
  @Prop({
    required: true,
    type: String,
    enum: Object.values(InvoiceRecipientType) as string[],
  })
  type!: InvoiceRecipientType;

  /**
   * For PLATFORM_BUSINESS: businessId
   * For PLATFORM_INDIVIDUAL: userId
   * For EXTERNAL: null/undefined (use email/name instead)
   */
  @Prop({ type: MongooseSchema.Types.ObjectId })
  platformId?: string;

  /**
   * Tenant database name if recipient is a registered platform business
   */
  @Prop({ type: String })
  tenantDatabaseName?: string;

  /**
   * Contact email - used for PLATFORM_INDIVIDUAL or EXTERNAL
   */
  @Prop({ type: String })
  email?: string;

  /**
   * For EXTERNAL: display name of business or person
   */
  @Prop({ type: String })
  displayName?: string;

  /**
   * Resolution status - whether platform identity is resolved
   */
  @Prop({
    type: String,
    enum: Object.values(RecipientResolutionStatus) as string[],
    default: RecipientResolutionStatus.RESOLVED,
  })
  resolutionStatus!: RecipientResolutionStatus;

  /**
   * Timestamp of last resolution attempt
   */
  @Prop({ type: Date })
  lastResolutionAttempt?: Date;
}

export const InvoiceRecipientSchema =
  SchemaFactory.createForClass(InvoiceRecipient);

/**
 * Invoice - Core financial document, owned and managed by issuer
 *
 * This is the authoritative source of truth for the invoice.
 * It lives in the issuing business's tenant database.
 * Recipients interact with read-only views or receipt records.
 */
@Schema({ collection: 'invoices', timestamps: true })
export class Invoice extends Document {
  /**
   * Issuer: The business that created and owns the invoice
   */
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
    index: true,
  })
  issuerBusinessId!: string;

  /**
   * Unique invoice number within the issuer's business
   * Auto-generated in format INV-{YYYYMMDD}-{randomString} if not provided
   */
  @Prop({ required: true })
  invoiceNumber!: string;

  /**
   * Recipient: Who the invoice is addressed to (business or individual)
   */
  @Prop({ required: true, type: InvoiceRecipientSchema })
  recipient!: InvoiceRecipient;

  /**
   * Lifecycle state of the invoice
   */
  @Prop({
    required: true,
    type: String,
    enum: Object.values(InvoiceStatus) as string[],
    default: InvoiceStatus.DRAFT,
    index: true,
  })
  status!: InvoiceStatus;

  /**
   * Financial details
   */
  @Prop({ required: true, type: Number })
  totalAmount!: number;

  @Prop({ required: true, type: String, default: 'TND' })
  currency!: string;

  /**
   * Payment tracking
   */
  @Prop({ type: Number, default: 0 })
  amountPaid!: number;

  @Prop({ type: [Date] })
  paymentDates?: Date[];

  /**
   * Dates
   */
  @Prop({ required: true, type: Date })
  issuedDate!: Date;

  @Prop({ required: true, type: Date })
  dueDate!: Date;

  /**
   * Line items that make up this invoice
   */
  @Prop({ type: [InvoiceLineItemSchema], default: [] })
  lineItems!: InvoiceLineItem[];

  /**
   * Description/memo
   */
  @Prop({ type: String })
  description?: string;

  /**
   * Payment terms / notes
   */
  @Prop({ type: String })
  paymentTerms?: string;

  /**
   * Void reason (if voided)
   */
  @Prop({ type: String })
  voidReason?: string;

  @Prop({ type: Date })
  voidedAt?: Date;

  /**
   * Reference to credit note if this invoice was amended/credited
   */
  @Prop({ type: [MongooseSchema.Types.ObjectId], default: [] })
  creditNoteIds?: string[];

  /**
   * Audit trail
   */
  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User' })
  createdBy?: string;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User' })
  lastModifiedBy?: string;

  @Prop({ type: Date })
  lastStatusChangeAt?: Date;

  /**
   * PDF Import Data
   */
  @Prop({
    type: String,
    enum: ['manual', 'pdf', 'csv', 'xlsx'],
    default: 'manual',
    index: true,
  })
  source?: string;

  @Prop({ type: MongooseSchema.Types.Mixed })
  extractionData?: any;

  @Prop({ type: Number, min: 0, max: 100 })
  confidenceScore?: number;

  @Prop({ type: String })
  pdfFilePath?: string;

  /**
   * Timestamps (auto-added by Mongoose @Schema({ timestamps: true }))
   */
  createdAt!: Date;
  updatedAt!: Date;
}

export const InvoiceSchema = SchemaFactory.createForClass(Invoice);

/**
 * Indexes for query efficiency
 */
InvoiceSchema.index({ issuerBusinessId: 1, status: 1 });
InvoiceSchema.index({ issuerBusinessId: 1, issuedDate: -1 });
InvoiceSchema.index(
  { invoiceNumber: 1, issuerBusinessId: 1 },
  { unique: true }
);
InvoiceSchema.index({ status: 1, dueDate: 1 }); // For overdue queries
InvoiceSchema.index({ 'recipient.email': 1 }); // For recipient lookup
InvoiceSchema.index({
  'recipient.platformId': 1,
  'recipient.type': 1,
  status: 1,
}); // For recipient discovery
