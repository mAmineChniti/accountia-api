import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';

/**
 * InvoiceReceipt - Cross-tenant discoverability record
 *
 * This record exists in the platform-level service and represents:
 * "Invoice X from Issuer A was issued to Recipient R"
 *
 * It is NOT the authoritative invoice (which lives in issuer's tenant).
 * It IS a lightweight index that helps recipients find invoices addressed to them.
 *
 * Recipients can query their InvoiceReceipts to find invoices, then
 * fetch the authoritative record from the issuer's tenant.
 *
 * This solves the cross-tenant visibility problem without replicating
 * the full invoice document.
 */
@Schema({ collection: 'invoice_receipts', timestamps: true })
export class InvoiceReceipt extends Document {
  /**
   * Reference to the authoritative invoice
   */
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    index: true,
  })
  invoiceId!: string;

  /**
   * Which tenant database holds the authoritative invoice
   */
  @Prop({ required: true })
  issuerTenantDatabaseName!: string;

  /**
   * Who issued the invoice
   */
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    index: true,
  })
  issuerBusinessId!: string;

  @Prop({ required: true })
  issuerBusinessName!: string;

  /**
   * Who receives the invoice - can be:
   * - A platform business (businessId)
   * - A platform individual (userId)
   * - An external contact (contactEmail)
   */
  @Prop({ type: MongooseSchema.Types.ObjectId, index: true })
  recipientBusinessId?: string; // If recipient is a PLATFORM_BUSINESS

  @Prop({ type: MongooseSchema.Types.ObjectId, index: true })
  recipientUserId?: string; // If recipient is a PLATFORM_INDIVIDUAL

  @Prop({ type: String, index: true })
  recipientEmail?: string; // For PLATFORM_INDIVIDUAL or EXTERNAL

  @Prop({ type: String })
  recipientDisplayName?: string; // For EXTERNAL

  /**
   * Lightweight invoice metadata for inbox display
   */
  @Prop({ required: true })
  invoiceNumber!: string;

  @Prop({ required: true, type: Number })
  totalAmount!: number;

  @Prop({ required: true })
  currency!: string;

  @Prop({ required: true, type: Date })
  issuedDate!: Date;

  @Prop({ required: true, type: Date })
  dueDate!: Date;

  /**
   * Current status of invoice
   */
  @Prop({
    required: true,
    type: String,
    enum: Object.values(InvoiceStatus) as string[],
    index: true,
  })
  invoiceStatus!: InvoiceStatus;

  /**
   * Recipient's view state
   */
  @Prop({ type: Boolean, default: false, index: true })
  recipientViewed!: boolean;

  @Prop({ type: Date })
  recipientViewedAt?: Date;

  /**
   * When this receipt record was last synced with the authoritative invoice
   */
  @Prop({ type: Date })
  lastSyncedAt!: Date;

  /**
   * Timestamps
   */
  createdAt!: Date;
  updatedAt!: Date;
}

export const InvoiceReceiptSchema =
  SchemaFactory.createForClass(InvoiceReceipt);

/**
 * Indexes for efficient inbox queries
 */
InvoiceReceiptSchema.index({ recipientBusinessId: 1, invoiceStatus: 1 });
InvoiceReceiptSchema.index({ recipientUserId: 1, invoiceStatus: 1 });
InvoiceReceiptSchema.index({ recipientEmail: 1, invoiceStatus: 1 });
InvoiceReceiptSchema.index({ recipientBusinessId: 1, issuedDate: -1 });
InvoiceReceiptSchema.index({ recipientUserId: 1, issuedDate: -1 });
InvoiceReceiptSchema.index({ recipientEmail: 1, issuedDate: -1 });
