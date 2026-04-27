import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum PurchaseOrderStatus {
  DRAFT = 'draft',
  PENDING_APPROVAL = 'pending_approval',
  APPROVED = 'approved',
  SENT = 'sent',
  PARTIALLY_RECEIVED = 'partially_received',
  RECEIVED = 'received',
  CLOSED = 'closed',
  CANCELLED = 'cancelled',
}

@Schema({ _id: true })
export class POLineItem extends Document {
  @Prop({
    required: false,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Product',
  })
  productId?: string;

  @Prop({ required: true })
  productName!: string;

  @Prop({ required: true, type: Number })
  orderedQuantity!: number;

  @Prop({ type: Number, default: 0 })
  receivedQuantity!: number;

  @Prop({ required: true, type: Number })
  unitPrice!: number;

  @Prop({ required: true, type: Number })
  amount!: number;

  @Prop({ type: String })
  description?: string;
}

export const POLineItemSchema = SchemaFactory.createForClass(POLineItem);

@Schema({ collection: 'purchase_orders', timestamps: true })
export class PurchaseOrder extends Document {
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
    index: true,
  })
  businessId!: string;

  @Prop({ required: true })
  poNumber!: string;

  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'Vendor' })
  vendorId!: string;

  @Prop({ required: true })
  vendorName!: string;

  @Prop({
    required: true,
    enum: PurchaseOrderStatus,
    default: PurchaseOrderStatus.DRAFT,
  })
  status!: PurchaseOrderStatus;

  @Prop({ type: [POLineItemSchema], default: [] })
  lineItems!: POLineItem[];

  @Prop({ required: true, type: Number })
  totalAmount!: number;

  @Prop({ required: true, default: 'TND' })
  currency!: string;

  @Prop({ required: true, type: Date })
  orderDate!: Date;

  @Prop({ type: Date })
  expectedDeliveryDate?: Date;

  @Prop({ type: Date })
  receivedAt?: Date;

  @Prop({ type: String })
  notes?: string;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User' })
  createdBy?: string;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User' })
  approvedBy?: string;

  @Prop({ type: Date })
  approvedAt?: Date;

  @Prop({ type: String })
  rejectionReason?: string;

  @Prop({ type: [String], default: [] })
  attachments!: string[];

  @Prop({ type: Date })
  lastStatusChangeAt?: Date;

  createdAt!: Date;
  updatedAt!: Date;
}

export const PurchaseOrderSchema = SchemaFactory.createForClass(PurchaseOrder);

PurchaseOrderSchema.index({ businessId: 1, status: 1 });
PurchaseOrderSchema.index({ businessId: 1, vendorId: 1 });
PurchaseOrderSchema.index({ businessId: 1, createdAt: -1 });
PurchaseOrderSchema.index({ businessId: 1, poNumber: 1 }, { unique: false });
