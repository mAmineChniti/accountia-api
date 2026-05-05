import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';

@Schema({ collection: 'business_users', timestamps: true })
export class BusinessUser extends Document {
  @Prop({ required: true })
  businessId: string;

  @Prop({ required: true })
  userId: string;

  @Prop({ required: true, type: String, enum: BusinessUserRole })
  role: BusinessUserRole;

  @Prop({ required: true })
  assignedBy: string; // User who assigned this role

  createdAt: Date;
  updatedAt: Date;
}

export const BusinessUserSchema = SchemaFactory.createForClass(BusinessUser);
BusinessUserSchema.index({ businessId: 1, userId: 1 }, { unique: true });
