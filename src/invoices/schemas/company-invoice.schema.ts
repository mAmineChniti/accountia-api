import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

@Schema({ collection: 'company_invoices', timestamps: true })
export class CompanyInvoice extends Document {
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
  })
  businessId!: string;

  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
  })
  clientBusinessId!: string;

  @Prop({ required: true })
  clientCompanyName!: string;

  @Prop({ required: true })
  clientContactEmail!: string;

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

export const CompanyInvoiceSchema =
  SchemaFactory.createForClass(CompanyInvoice);

// Indexes for common queries
CompanyInvoiceSchema.index({ businessId: 1 });
CompanyInvoiceSchema.index({ clientBusinessId: 1 });
CompanyInvoiceSchema.index({ businessId: 1, paid: 1 });
CompanyInvoiceSchema.index({ businessId: 1, issuedAt: -1 });
CompanyInvoiceSchema.index({ clientBusinessId: 1, issuedAt: -1 });
