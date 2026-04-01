import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export type TransactionDocument = Transaction & Document;

@Schema({ timestamps: true })
export class Transaction {
  @Prop({ required: true })
  transactionId: string;

  @Prop({ required: true })
  date: Date;

  @Prop({ required: true })
  accountType: string;

  @Prop({ required: true })
  amount: number;

  @Prop({ required: true })
  cashFlow: number;

  @Prop({ required: true })
  netIncome: number;

  @Prop({ required: true })
  revenue: number;

  @Prop({ required: true })
  expenditure: number;

  @Prop({ required: true })
  profitMargin: number;

  @Prop({ required: true })
  operatingExpenses: number;

  @Prop({ required: true })
  grossProfit: number;

  @Prop({ required: true })
  accuracyScore: number;

  @Prop({ default: false })
  hasMissingData: boolean;

  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
  })
  businessId: string;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User' })
  clientId?: string;
}

export const TransactionSchema = SchemaFactory.createForClass(Transaction);
