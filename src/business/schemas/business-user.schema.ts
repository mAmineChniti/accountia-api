import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum BusinessUserRole {
  OWNER = 'owner',
  ADMIN = 'admin',
}

@Schema({ collection: 'business_users', timestamps: true })
export class BusinessUser {
  @Prop({ required: true })
  businessId: string;

  @Prop({ required: true })
  userId: string;

  @Prop({ required: true, enum: BusinessUserRole })
  role: BusinessUserRole;

  @Prop({ required: true })
  assignedBy: string; // User who assigned this role

  @Prop({ default: true })
  isActive: boolean;

  createdAt: Date;
  updatedAt: Date;
}

export type BusinessUserDocument = BusinessUser & Document;
export const BusinessUserSchema = SchemaFactory.createForClass(BusinessUser);
BusinessUserSchema.index({ businessId: 1, userId: 1 }, { unique: true });
