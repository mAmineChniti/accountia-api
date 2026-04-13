import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

@Schema({ collection: 'portal_tokens', timestamps: true })
export class PortalToken extends Document {
  @Prop({ required: true, unique: true, index: true })
  token!: string;

  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'Business' })
  businessId!: string;

  @Prop({ required: true })
  clientEmail!: string;

  @Prop({ type: String })
  clientName?: string;

  @Prop({ required: true, type: Date, index: true })
  expiresAt!: Date;

  @Prop({ type: Date })
  lastAccessedAt?: Date;

  createdAt!: Date;
  updatedAt!: Date;
}

export const PortalTokenSchema = SchemaFactory.createForClass(PortalToken);
PortalTokenSchema.index({ token: 1, expiresAt: 1 });
PortalTokenSchema.index({ businessId: 1, clientEmail: 1 });
