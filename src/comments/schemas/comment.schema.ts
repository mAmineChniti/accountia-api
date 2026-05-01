import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum CommentEntityType {
  INVOICE = 'invoice',
  EXPENSE = 'expense',
  PURCHASE_ORDER = 'purchase_order',
}

@Schema({ collection: 'comments', timestamps: true })
export class Comment extends Document {
  @Prop({
    required: true,
    type: MongooseSchema.Types.ObjectId,
    ref: 'Business',
    index: true,
  })
  businessId!: string;

  @Prop({ required: true, enum: CommentEntityType })
  entityType!: CommentEntityType;

  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, index: true })
  entityId!: string;

  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'User' })
  authorId!: string;

  @Prop({ required: true })
  authorName!: string;

  @Prop({ required: true })
  body!: string;

  @Prop({ type: MongooseSchema.Types.ObjectId, default: null })
  parentId?: string | null;

  @Prop({ type: [String], default: [] })
  mentions!: string[];

  @Prop({ type: Boolean, default: false })
  isEdited!: boolean;

  @Prop({ type: Boolean, default: false })
  isDeleted!: boolean;

  createdAt!: Date;
  updatedAt!: Date;
}

export const CommentSchema = SchemaFactory.createForClass(Comment);

CommentSchema.index({ businessId: 1, entityType: 1, entityId: 1 });
CommentSchema.index({
  businessId: 1,
  entityType: 1,
  entityId: 1,
  createdAt: 1,
});
