import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum InvoiceStatus {
  DRAFT = 'DRAFT',
  SENT = 'SENT',
  PAID = 'PAID',
  PENDING = 'PENDING',
  OVERDUE = 'OVERDUE',
}

@Schema({ _id: false })
export class InvoiceItem {
  @Prop({ required: true })
  id: string;

  @Prop({ required: true })
  description: string;

  @Prop({ required: true, type: Number })
  quantity: number;

  @Prop({ required: true, type: Number })
  unitPrice: number;

  @Prop({ required: true, type: Number })
  total: number;
}

export const InvoiceItemSchema = SchemaFactory.createForClass(InvoiceItem);

export type InvoiceDocument = Invoice & Document;

@Schema({ timestamps: true })
export class Invoice {
  @Prop({ required: true, unique: true, index: true })
  invoiceNumber: string;

  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
    index: true,
  })
  businessOwnerId: string;

  @Prop({ required: true })
  clientName: string;

  @Prop({ required: true })
  clientEmail: string;

  @Prop()
  clientPhone?: string;

  @Prop({ type: [InvoiceItemSchema], required: true })
  lineItems: InvoiceItem[];

  @Prop({ required: true, type: Number, default: 0 })
  subtotal: number;

  @Prop({ required: true, type: Number, default: 0 })
  taxRate: number;

  @Prop({ required: true, type: Number, default: 0 })
  taxAmount: number;

  @Prop({ required: true, type: Number, default: 0 })
  total: number;

  @Prop({ required: true })
  issueDate: Date;

  @Prop({ required: true })
  dueDate: Date;

  @Prop({
    required: true,
    enum: Object.values(InvoiceStatus),
    default: InvoiceStatus.DRAFT,
  })
  status: InvoiceStatus;

  @Prop()
  notes?: string;

  @Prop({ default: 'TND' })
  currency: string;

  @Prop()
  sentAt?: Date;

  @Prop()
  paidAt?: Date;

  @Prop()
  deletedAt?: Date;

  @Prop({ default: false })
  remindersMuted: boolean;

  @Prop({
    type: [
      {
        sentAt: { type: Date, default: Date.now },
        intervalDays: Number,
      },
    ],
    _id: false,
    default: [],
  })
  reminderHistory: { sentAt: Date; intervalDays: number }[];

  @Prop({ index: true })
  createdAt?: Date;

  @Prop()
  updatedAt?: Date;
}

export const InvoiceSchema = SchemaFactory.createForClass(Invoice);

// Créer un index composé pour les requêtes fréquentes
InvoiceSchema.index({ businessOwnerId: 1, status: 1 });
InvoiceSchema.index({ businessOwnerId: 1, createdAt: -1 });
