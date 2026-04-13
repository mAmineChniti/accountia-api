import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum RecurringFrequency {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
  QUARTERLY = 'quarterly',
  YEARLY = 'yearly',
}

export enum RecurringStatus {
  ACTIVE = 'active',
  PAUSED = 'paused',
  CANCELLED = 'cancelled',
  COMPLETED = 'completed',
}

export enum RecurringEndCondition {
  NEVER = 'never',
  AFTER_OCCURRENCES = 'after_occurrences',
  BY_DATE = 'by_date',
}

@Schema({ _id: false })
export class RecurringLineItem {
  @Prop({ required: false, type: MongooseSchema.Types.ObjectId, ref: 'Product' })
  productId?: string;

  @Prop({ required: true })
  productName!: string;

  @Prop({ required: true, type: Number })
  quantity!: number;

  @Prop({ required: true, type: Number })
  unitPrice!: number;

  @Prop({ required: true, type: Number })
  amount!: number;

  @Prop({ type: String })
  description?: string;
}

export const RecurringLineItemSchema = SchemaFactory.createForClass(RecurringLineItem);

@Schema({ collection: 'recurring_invoices', timestamps: true })
export class RecurringInvoice extends Document {
  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'Business', index: true })
  businessId!: string;

  @Prop({ required: true })
  name!: string;

  @Prop({ required: true, enum: RecurringFrequency })
  frequency!: RecurringFrequency;

  @Prop({ required: true, enum: RecurringStatus, default: RecurringStatus.ACTIVE })
  status!: RecurringStatus;

  @Prop({ required: true, type: Date })
  startDate!: Date;

  @Prop({ required: true, enum: RecurringEndCondition, default: RecurringEndCondition.NEVER })
  endCondition!: RecurringEndCondition;

  @Prop({ type: Number })
  maxOccurrences?: number;

  @Prop({ type: Number, default: 0 })
  occurrenceCount!: number;

  @Prop({ type: Date })
  endDate?: Date;

  @Prop({ required: true, type: Date })
  nextRunAt!: Date;

  @Prop({ type: Date })
  lastRunAt?: Date;

  @Prop({ type: [RecurringLineItemSchema], default: [] })
  lineItems!: RecurringLineItem[];

  @Prop({ required: true, type: Number })
  totalAmount!: number;

  @Prop({ required: true, default: 'TND' })
  currency!: string;

  @Prop({ type: Number, default: 30 })
  dueDaysFromIssue!: number;

  @Prop({ type: Object, required: true })
  recipient!: Record<string, unknown>;

  @Prop({ type: String })
  description?: string;

  @Prop({ type: String })
  paymentTerms?: string;

  @Prop({ type: Boolean, default: false })
  autoIssue!: boolean;

  @Prop({ type: [MongooseSchema.Types.ObjectId], default: [] })
  generatedInvoiceIds!: string[];

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User' })
  createdBy?: string;

  createdAt!: Date;
  updatedAt!: Date;
}

export const RecurringInvoiceSchema = SchemaFactory.createForClass(RecurringInvoice);

RecurringInvoiceSchema.index({ businessId: 1, status: 1 });
RecurringInvoiceSchema.index({ status: 1, nextRunAt: 1 });
RecurringInvoiceSchema.index({ businessId: 1, createdAt: -1 });
