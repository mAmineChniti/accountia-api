import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';

@Schema({ collection: 'business_invites', timestamps: true })
export class BusinessInvite extends Document {
  @Prop({ required: true })
  businessId: string;

  @Prop({
    required: true,
    lowercase: true,
    trim: true,
  })
  invitedEmail: string;

  @Prop({ required: true })
  inviterId: string; // User who sent the invite

  @Prop({
    required: true,
    type: String,
    enum: [
      BusinessUserRole.ADMIN,
      BusinessUserRole.MEMBER,
      BusinessUserRole.CLIENT,
    ],
  })
  businessRole: BusinessUserRole;

  @Prop({ default: false })
  emailSent: boolean;

  @Prop({
    type: String,
    enum: ['pending', 'accepted', 'revoked'],
    default: 'pending',
  })
  status: 'pending' | 'accepted' | 'revoked';

  @Prop()
  acceptedAt?: Date;

  @Prop()
  processedBy?: string;

  @Prop()
  expiresAt?: Date;

  createdAt: Date;
  updatedAt: Date;
}

export const BusinessInviteSchema =
  SchemaFactory.createForClass(BusinessInvite);
// Allow multiple invites for same email to different businesses
BusinessInviteSchema.index({ invitedEmail: 1 });
BusinessInviteSchema.index({ businessId: 1 });
BusinessInviteSchema.index(
  { invitedEmail: 1, businessId: 1 },
  { unique: true }
);
