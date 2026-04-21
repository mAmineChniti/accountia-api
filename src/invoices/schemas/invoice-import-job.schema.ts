/* eslint-disable unicorn/no-abusive-eslint-disable */
/* eslint-disable */
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum ImportJobStatus {
  PENDING = 'PENDING',
  PROCESSING = 'PROCESSING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

@Schema({ collection: 'invoice_import_jobs', timestamps: true })
export class InvoiceImportJob extends Document {
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
    index: true,
  })
  businessId!: string;

  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'User',
    index: true,
  })
  userId!: string;

  @Prop({
    required: true,
    type: String,
    enum: Object.values(ImportJobStatus),
    default: ImportJobStatus.PENDING,
  })
  status!: ImportJobStatus;

  @Prop({ type: String })
  pdfFilePath!: string;

  @Prop({ type: String })
  originalFilename!: string;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'Invoice' })
  invoiceId?: string;

  @Prop({ type: String })
  error?: string;

  @Prop({ type: MongooseSchema.Types.Mixed })
  metadata?: any;

  createdAt!: Date;
  updatedAt!: Date;
}

export const InvoiceImportJobSchema =
  SchemaFactory.createForClass(InvoiceImportJob);
