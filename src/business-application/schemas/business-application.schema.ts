import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export enum ApplicationStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
}

export type BusinessApplicationDocument = BusinessApplication & Document;

@Schema({ collection: 'business_applications', timestamps: true })
export class BusinessApplication {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, unique: true })
  userId: Types.ObjectId;

  @Prop({ required: true })
  businessName: string;

  @Prop({ required: true })
  businessType: string;

  @Prop({ required: true })
  description: string;

  @Prop()
  website?: string;

  @Prop({
    type: String,
    enum: ApplicationStatus,
    default: ApplicationStatus.PENDING,
  })
  status: ApplicationStatus;

  @Prop()
  createdAt: Date;

  @Prop()
  updatedAt: Date;
}

export const BusinessApplicationSchema =
  SchemaFactory.createForClass(BusinessApplication);
