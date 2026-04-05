import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

@Schema({ collection: 'products', timestamps: true })
export class Product extends Document {
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
  })
  businessId!: string;

  @Prop({ required: true })
  name!: string;

  @Prop({ required: true })
  description!: string;

  @Prop({ required: true, type: Number })
  unitPrice!: number;

  @Prop({ type: Number, default: 0 })
  cost!: number;

  @Prop({ required: true, type: Number })
  quantity!: number;

  @Prop({ required: true, default: 'TND' })
  currency!: string;

  createdAt!: Date;
  updatedAt!: Date;
}

export const ProductSchema = SchemaFactory.createForClass(Product);

// Indexes for common queries
ProductSchema.index({ businessId: 1 });
ProductSchema.index({ businessId: 1, name: 1 });
ProductSchema.index({ businessId: 1, createdAt: -1 });
