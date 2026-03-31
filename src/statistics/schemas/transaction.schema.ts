import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { ApiPropertyOptional } from '@nestjs/swagger';

export type TransactionDocument = Transaction & Document;

@Schema({ collection: 'transactions' })
export class Transaction {
  @ApiPropertyOptional({ example: '1' })
  @Prop({ name: 'Transaction ID', required: false })
  transactionId?: string;

  @ApiPropertyOptional({ example: 'client-uuid' })
  @Prop({ required: false })
  clientId?: string;

  @ApiPropertyOptional({ example: '2025-01-01' })
  @Prop({ name: 'Date', required: false })
  date?: Date;

  @ApiPropertyOptional({
    example: 'Asset',
    enum: ['Asset', 'Expense', 'Revenue', 'Liability'],
  })
  @Prop({ name: 'Account Type', required: false })
  accountType?: string;

  @ApiPropertyOptional({ example: 1176 })
  @Prop({ name: 'Transaction Amount', required: false })
  transactionAmount?: number;

  @ApiPropertyOptional({ example: 2174 })
  @Prop({ name: 'Net Income', required: false })
  netIncome?: number;

  @ApiPropertyOptional({ example: 3137 })
  @Prop({ name: 'Revenue', required: false })
  revenue?: number;

  @ApiPropertyOptional({ example: 1823 })
  @Prop({ name: 'Expenditure', required: false })
  expenditure?: number;

  @ApiPropertyOptional({ example: 0.6072 })
  @Prop({ name: 'Profit Margin', required: false })
  profitMargin?: number;

  @ApiPropertyOptional({ example: 0.9599 })
  @Prop({ name: 'Accuracy Score', required: false })
  accuracyScore?: number;

  @ApiPropertyOptional({ example: 1 })
  @Prop({ name: 'Transaction Outcome', required: false })
  transactionOutcome?: number;

  @ApiPropertyOptional({ example: 'USD' })
  @Prop({ required: false, default: 'USD' })
  originalCurrency?: string;

  @ApiPropertyOptional({ example: 'USD' })
  @Prop({ required: false, default: 'USD' })
  convertedCurrency?: string;

  @ApiPropertyOptional({ example: 1 })
  @Prop({ required: false, default: 1 })
  exchangeRate?: number;

  @ApiPropertyOptional({ example: 1176 })
  @Prop({ required: false })
  convertedAmount?: number;
}

export const TransactionSchema = SchemaFactory.createForClass(Transaction);
