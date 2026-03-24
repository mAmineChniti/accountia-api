import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ collection: 'business_applications', timestamps: true })
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

  @Prop({ required: false })
  applicantEmail?: string; // Email for notifications

  @Prop({ required: false })
  applicantName?: string; // Name for personalized emails

  @Prop({
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending',
  })
  status: 'pending' | 'approved' | 'rejected';

  @Prop({ required: false })
  reviewedBy?: string; // Platform admin/owner who reviewed

  @Prop({ required: false })
  reviewNotes?: string;

  @Prop({ required: false })
  businessId?: string; // Reference to created business if approved

  createdAt: Date;
  updatedAt: Date;
}

export type BusinessApplicationDocument = BusinessApplication & Document;
export const BusinessApplicationSchema =
  SchemaFactory.createForClass(BusinessApplication);

// Add compound index to ensure one pending application per user
BusinessApplicationSchema.index(
  { applicantId: 1, status: 1 },
  { unique: false }
);
