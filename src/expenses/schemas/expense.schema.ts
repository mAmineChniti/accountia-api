import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum ExpenseStatus {
  DRAFT = 'draft',
  SUBMITTED = 'submitted',
  APPROVED = 'approved',
  REJECTED = 'rejected',
  REIMBURSED = 'reimbursed',
}

export enum ExpenseCategory {
  TRAVEL = 'travel',
  MEALS = 'meals',
  ACCOMMODATION = 'accommodation',
  OFFICE_SUPPLIES = 'office_supplies',
  SOFTWARE = 'software',
  HARDWARE = 'hardware',
  MARKETING = 'marketing',
  UTILITIES = 'utilities',
  PROFESSIONAL_SERVICES = 'professional_services',
  OTHER = 'other',
}

@Schema({ collection: 'expenses', timestamps: true })
export class Expense extends Document {
  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'Business', index: true })
  businessId!: string;

  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'User' })
  submittedBy!: string;

  @Prop({ required: true })
  submittedByName!: string;

  @Prop({ required: true })
  title!: string;

  @Prop({ required: true, type: Number })
  amount!: number;

  @Prop({ required: true, default: 'TND' })
  currency!: string;

  @Prop({ required: true, enum: ExpenseCategory })
  category!: ExpenseCategory;

  @Prop({ required: true, type: Date })
  expenseDate!: Date;

  @Prop({ type: String })
  description?: string;

  @Prop({ type: String })
  vendor?: string;

  @Prop({ type: String })
  receiptBase64?: string;

  @Prop({ type: String })
  receiptMimeType?: string;

  @Prop({ required: true, enum: ExpenseStatus, default: ExpenseStatus.DRAFT })
  status!: ExpenseStatus;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User' })
  reviewedBy?: string;

  @Prop({ type: String })
  reviewNotes?: string;

  @Prop({ type: Date })
  reviewedAt?: Date;

  @Prop({ type: Date })
  reimbursedAt?: Date;

  @Prop({ type: Boolean, default: false })
  isBillable!: boolean;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'Invoice' })
  linkedInvoiceId?: string;

  createdAt!: Date;
  updatedAt!: Date;
}

export const ExpenseSchema = SchemaFactory.createForClass(Expense);

ExpenseSchema.index({ businessId: 1, status: 1 });
ExpenseSchema.index({ businessId: 1, submittedBy: 1 });
ExpenseSchema.index({ businessId: 1, category: 1 });
ExpenseSchema.index({ businessId: 1, expenseDate: -1 });
