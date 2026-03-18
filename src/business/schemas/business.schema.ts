import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ collection: 'businesses', timestamps: true })
export class Business {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  description: string;

  @Prop()
  website?: string;

  @Prop({ required: true })
  phone: string;

  @Prop({ required: true, unique: true })
  databaseName: string; // Multi-tenant database identifier

  @Prop({
    type: String,
    enum: ['pending', 'approved', 'rejected', 'suspended'],
    default: 'pending',
  })
  status: 'pending' | 'approved' | 'rejected' | 'suspended';

  @Prop({ default: false })
  isActive: boolean;

  @Prop()
  logo?: string;

  @Prop([String])
  tags: string[];

  createdAt: Date;
  updatedAt: Date;
}

export type BusinessDocument = Business & Document;
export const BusinessSchema = SchemaFactory.createForClass(Business);
