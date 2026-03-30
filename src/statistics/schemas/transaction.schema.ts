import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { ApiProperty } from '@nestjs/swagger';

export type TransactionDocument = Transaction & Document;

@Schema({ collection: 'transactions' })
export class Transaction {
  @ApiProperty({ example: '1' })
  @Prop({ name: 'Transaction ID', required: false })
  transactionId: string;

  @ApiProperty({ example: 'client-uuid' })
  @Prop({ required: false })
  clientId?: string;

  @ApiProperty({ example: '2025-01-01' })
  @Prop({ name: 'Date', required: false })
  date: Date;

  @ApiProperty({ example: 'Asset', enum: ['Asset', 'Expense', 'Revenue', 'Liability'] })
  @Prop({ name: 'Account Type', required: false })
  accountType: string;

  @ApiProperty({ example: 1176 })
  @Prop({ name: 'Transaction Amount', required: false })
  transactionAmount: number;

  @ApiProperty({ example: 2174 })
  @Prop({ name: 'Net Income', required: false })
  netIncome: number;

  @ApiProperty({ example: 3137 })
  @Prop({ name: 'Revenue', required: false })
  revenue: number;

  @ApiProperty({ example: 1823 })
  @Prop({ name: 'Expenditure', required: false })
  expenditure: number;

  @ApiProperty({ example: 0.6072 })
  @Prop({ name: 'Profit Margin', required: false })
  profitMargin: number;

  @ApiProperty({ example: 0.9599 })
  @Prop({ name: 'Accuracy Score', required: false })
  accuracyScore: number;

  @ApiProperty({ example: 1 })
  @Prop({ name: 'Transaction Outcome', required: false })
  transactionOutcome: number;

  @ApiProperty({ example: 'USD' })
  @Prop({ required: false, default: 'USD' })
  originalCurrency: string;

  @ApiProperty({ example: 'USD' })
  @Prop({ required: false, default: 'USD' })
  convertedCurrency: string;

  @ApiProperty({ example: 1.0 })
  @Prop({ required: false, default: 1.0 })
  exchangeRate: number;

  @ApiProperty({ example: 1176 })
  @Prop({ required: false })
  convertedAmount: number;
}

export const TransactionSchema = SchemaFactory.createForClass(Transaction);
