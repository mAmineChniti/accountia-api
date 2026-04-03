import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

@Schema({ collection: 'personal_invoices', timestamps: true })
export class PersonalInvoice extends Document {
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
  })
  businessId!: string;

  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'User',
  })
  clientUserId!: string;

  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Product',
  })
  productId!: string;

  @Prop({ required: true, type: Number })
  quantity!: number;

  @Prop({ required: true, type: Number })
  amount!: number;

  @Prop({ required: true, type: Date })
  issuedAt!: Date;

  @Prop({ required: true, type: Boolean, default: false })
  paid!: boolean;

  @Prop({ type: Date })
  paidAt?: Date;

  createdAt!: Date;
  updatedAt!: Date;
}

export const PersonalInvoiceSchema =
  SchemaFactory.createForClass(PersonalInvoice);

// Indexes for common queries
PersonalInvoiceSchema.index({ businessId: 1 });
PersonalInvoiceSchema.index({ businessId: 1, paid: 1 });
PersonalInvoiceSchema.index({ clientUserId: 1 });
PersonalInvoiceSchema.index({ businessId: 1, issuedAt: -1 });
