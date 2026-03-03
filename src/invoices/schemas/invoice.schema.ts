import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export enum InvoiceStatus {
  DRAFT = 'DRAFT',
  PENDING = 'PENDING',
  PAID = 'PAID',
  OVERDUE = 'OVERDUE',
  CANCELLED = 'CANCELLED',
}

export type InvoiceDocument = Invoice & Document;

@Schema({ collection: 'invoices', timestamps: true })
export class Invoice {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  clientId: Types.ObjectId;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  businessOwnerId: Types.ObjectId;

  @Prop({ required: true })
  invoiceNumber: string;

  @Prop({ required: true })
  description: string;

  @Prop({ required: true })
  amount: number;

  @Prop({ default: 'USD' })
  currency: string;

  @Prop({
    type: String,
    enum: InvoiceStatus,
    default: InvoiceStatus.PENDING,
  })
  status: InvoiceStatus;

  @Prop({ type: Date, required: true })
  dueDate: Date;

  @Prop({ type: Date })
  paidAt?: Date;

  @Prop()
  notes?: string;

  @Prop()
  createdAt: Date;

  @Prop()
  updatedAt?: Date;
}

export const InvoiceSchema = SchemaFactory.createForClass(Invoice);

// Add compound unique index on invoiceNumber and businessOwnerId
InvoiceSchema.index({ invoiceNumber: 1, businessOwnerId: 1 }, { unique: true });
