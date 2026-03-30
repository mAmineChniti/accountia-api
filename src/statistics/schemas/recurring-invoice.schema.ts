import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { ApiProperty } from '@nestjs/swagger';

export type RecurringInvoiceDocument = RecurringInvoice & Document;

export enum RecurringFrequency {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
  QUARTERLY = 'quarterly',
  ANNUALLY = 'annually',
}

export enum RecurringStatus {
  ACTIVE = 'active',
  PAUSED = 'paused',
  CANCELLED = 'cancelled',
}

@Schema()
export class InvoiceItem {
  @Prop({ required: true })
  description: string;

  @Prop({ required: true })
  quantity: number;

  @Prop({ required: true })
  price: number;
}
const InvoiceItemSchema = SchemaFactory.createForClass(InvoiceItem);

@Schema({ collection: 'recurring_invoices', timestamps: true })
export class RecurringInvoice {
  @ApiProperty({ example: 'client123' })
  @Prop({ required: true })
  clientId: string;

  @ApiProperty({ example: 'John Doe' })
  @Prop({ required: true })
  clientName: string;

  @ApiProperty({ example: 'john@example.com' })
  @Prop({ required: false })
  clientEmail: string;

  @ApiProperty({ type: [InvoiceItem] })
  @Prop({ type: [InvoiceItemSchema], required: true })
  items: InvoiceItem[];

  @ApiProperty({ example: 1000 })
  @Prop({ required: true })
  totalAmount: number;

  @ApiProperty({ example: 'monthly', enum: RecurringFrequency })
  @Prop({ required: true, enum: RecurringFrequency })
  frequency: RecurringFrequency;

  @ApiProperty({ example: 'template123' })
  @Prop({ required: true })
  templateId: string;

  @ApiProperty({ example: '2026-04-01T00:00:00Z' })
  @Prop({ required: true })
  startDate: Date;

  @ApiProperty({ example: '2027-04-01T00:00:00Z', required: false })
  @Prop({ required: false })
  endDate?: Date;

  @ApiProperty({ example: '2026-05-01T00:00:00Z' })
  @Prop({ required: true })
  nextRunDate: Date;

  @ApiProperty({ example: 'active', enum: RecurringStatus })
  @Prop({ required: true, enum: RecurringStatus, default: RecurringStatus.ACTIVE })
  status: RecurringStatus;

  @ApiProperty({ example: true })
  @Prop({ required: true, default: false })
  autoSend: boolean;
}

export const RecurringInvoiceSchema = SchemaFactory.createForClass(RecurringInvoice);
