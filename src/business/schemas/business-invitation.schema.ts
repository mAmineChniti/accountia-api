import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';

export enum InvitationStatus {
  PENDING = 'PENDING',
  ACCEPTED = 'ACCEPTED',
  CANCELLED = 'CANCELLED',
}

@Schema({ collection: 'business_invitations', timestamps: true })
export class BusinessInvitation extends Document {
  @Prop({ required: true })
  token: string;

  @Prop({ required: true })
  email: string;

  @Prop({ required: true })
  businessId: string;

  @Prop({ required: true, type: String, enum: BusinessUserRole })
  role: BusinessUserRole;

  @Prop({ required: true })
  invitedBy: string;

  @Prop({
    required: true,
    type: String,
    enum: InvitationStatus,
    default: InvitationStatus.PENDING,
  })
  status: InvitationStatus;

  @Prop({ required: true })
  expiresAt: Date;

  createdAt: Date;
  updatedAt: Date;
}

export const BusinessInvitationSchema =
  SchemaFactory.createForClass(BusinessInvitation);
BusinessInvitationSchema.index({ email: 1, businessId: 1, status: 1 });
BusinessInvitationSchema.index({ token: 1 }, { unique: true });
