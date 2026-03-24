import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum NotificationType {
  NEW_BUSINESS_APPLICATION = 'NEW_BUSINESS_APPLICATION',
  BUSINESS_APPROVED = 'BUSINESS_APPROVED',
  BUSINESS_REJECTED = 'BUSINESS_REJECTED',
  USER_BANNED = 'USER_BANNED',
}

@Schema({ timestamps: true, collection: 'notifications' })
export class Notification extends Document {
  @Prop({ required: true, enum: NotificationType })
  type: NotificationType;

  @Prop({ required: true })
  message: string;

  @Prop({ type: Object, default: {} })
  payload: Record<string, any>;

  @Prop({ default: false })
  isRead: boolean;

  createdAt: Date;
  updatedAt: Date;
}

export const NotificationSchema = SchemaFactory.createForClass(Notification);
NotificationSchema.index({ isRead: 1, createdAt: -1 });
