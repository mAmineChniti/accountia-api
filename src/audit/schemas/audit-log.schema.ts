import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum AuditAction {
  LOGIN = 'LOGIN',
  REGISTER = 'REGISTER',
  APPROVE_BUSINESS = 'APPROVE_BUSINESS',
  REJECT_BUSINESS = 'REJECT_BUSINESS',
  BAN_USER = 'BAN_USER',
  DELETE_BUSINESS = 'DELETE_BUSINESS',
  CREATE_BUSINESS = 'CREATE_BUSINESS',
  OTHER = 'OTHER',
}

@Schema({ timestamps: true, collection: 'audit_logs' })
export class AuditLog extends Document {
  @Prop({ required: true, enum: AuditAction })
  action: AuditAction;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User', required: true })
  userId: string; // Utilisateur qui fait l'action

  @Prop({ required: true })
  userEmail: string;

  @Prop({ required: true })
  userRole: string;

  @Prop({ type: Object })
  details: Record<string, any>; // Détails supplémentaires dynamiques

  @Prop()
  target?: string; // Who/what was the target of the action (email, business name, etc.)

  @Prop()
  ipAddress?: string;

  createdAt: Date;
  updatedAt: Date;
}

export const AuditLogSchema = SchemaFactory.createForClass(AuditLog);

// Indexing pour optimiser la recherche par un Compliance Officer
AuditLogSchema.index({ action: 1, createdAt: -1 });
AuditLogSchema.index({ createdAt: -1 });
