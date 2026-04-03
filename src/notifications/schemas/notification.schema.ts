import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum NotificationType {
  NEW_BUSINESS_APPLICATION = 'NEW_BUSINESS_APPLICATION',
  BUSINESS_APPROVED = 'BUSINESS_APPROVED',
  BUSINESS_REJECTED = 'BUSINESS_REJECTED',
  USER_BANNED = 'USER_BANNED',
  INVOICE_CREATED = 'INVOICE_CREATED',
}

@Schema({ timestamps: true, collection: 'notifications' })
export class Notification extends Document {
  @Prop({ required: true, enum: NotificationType })
  type: NotificationType;

  @Prop({ required: true })
  message: string;

  @Prop({ type: String, required: false })
  targetBusinessId?: string; // If set, this notification is targeted specifically to a business owner

  @Prop({ type: String, required: false })
  targetUserEmail?: string; // If set, this notification is targeted to a specific user (e.g. managed client)

  @Prop({ type: Object, default: {} })
  payload: Record<string, unknown>;

  @Prop({ default: false })
  isRead: boolean;

  createdAt: Date;
  updatedAt: Date;
}

export const NotificationSchema = SchemaFactory.createForClass(Notification);
NotificationSchema.index({ isRead: 1, createdAt: -1 });
NotificationSchema.index({ targetBusinessId: 1, createdAt: -1 });
NotificationSchema.index({ targetUserEmail: 1, createdAt: -1 });
