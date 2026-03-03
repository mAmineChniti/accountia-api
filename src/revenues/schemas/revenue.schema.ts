import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type RevenueDocument = Revenue & Document;

@Schema({ timestamps: true })
export class Revenue {
  @Prop({ required: true })
  amount: number;

  @Prop({ required: true })
  date: Date;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  user: Types.ObjectId;
}

export const RevenueSchema = SchemaFactory.createForClass(Revenue);