import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum VendorStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  BLOCKED = 'blocked',
}

@Schema({ collection: 'vendors', timestamps: true })
export class Vendor extends Document {
  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'Business', index: true })
  businessId!: string;

  @Prop({ required: true })
  name!: string;

  @Prop({ type: String })
  contactName?: string;

  @Prop({ type: String })
  email?: string;

  @Prop({ type: String })
  phone?: string;

  @Prop({ type: String })
  address?: string;

  @Prop({ type: String })
  taxId?: string;

  @Prop({ type: String })
  website?: string;

  @Prop({ type: Number, default: 30 })
  paymentTermsDays!: number;

  @Prop({ required: true, enum: VendorStatus, default: VendorStatus.ACTIVE })
  status!: VendorStatus;

  @Prop({ type: String })
  notes?: string;

  @Prop({ type: Number, default: 0 })
  totalOrders!: number;

  @Prop({ type: Number, default: 0 })
  totalSpend!: number;

  @Prop({ type: Number, min: 1, max: 5 })
  rating?: number;

  createdAt!: Date;
  updatedAt!: Date;
}

export const VendorSchema = SchemaFactory.createForClass(Vendor);

VendorSchema.index({ businessId: 1, status: 1 });
VendorSchema.index({ businessId: 1, name: 1 });
VendorSchema.index({ businessId: 1, createdAt: -1 });
