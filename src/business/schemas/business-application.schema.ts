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

  @Prop({
    type: [
      {
        action: { type: String, required: true },
        reviewedBy: { type: String, required: true },
        reviewerName: { type: String, required: true },
        notes: { type: String },
        timestamp: { type: Date, default: Date.now },
      },
    ],
    default: [],
  })
  reviewHistory: Array<{
    action: string;
    reviewedBy: string;
    reviewerName: string;
    notes: string;
    timestamp: Date;
  }>;

  createdAt: Date;
  updatedAt: Date;
}

export type BusinessApplicationDocument = BusinessApplication & Document;
export const BusinessApplicationSchema =
  SchemaFactory.createForClass(BusinessApplication);
