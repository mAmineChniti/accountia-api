import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum BusinessUserRole {
  OWNER = 'owner',
  ADMIN = 'admin',
}

@Schema({ timestamps: true })
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

  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}

export type BusinessUserDocument = BusinessUser & Document;
export const BusinessUserSchema = SchemaFactory.createForClass(BusinessUser);
