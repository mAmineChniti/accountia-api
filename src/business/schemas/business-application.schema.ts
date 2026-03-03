import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class BusinessApplication {
  @Prop({ required: true })
  businessName: string;

  @Prop({ required: true })
  description: string;

  @Prop()
  website?: string;

  @Prop({ required: true })
  phone: string;

  @Prop({ required: true })
  applicantId: string; // User who submitted the application

  @Prop({ default: 'pending' })
  status: 'pending' | 'approved' | 'rejected';

  @Prop({ required: false })
  reviewedBy?: string; // Platform admin/owner who reviewed

  @Prop({ required: false })
  reviewNotes?: string;

  @Prop({ required: false })
  businessId?: string; // Reference to created business if approved

  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}

export type BusinessApplicationDocument = BusinessApplication & Document;
export const BusinessApplicationSchema =
  SchemaFactory.createForClass(BusinessApplication);
