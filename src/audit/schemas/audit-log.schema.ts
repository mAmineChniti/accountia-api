import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum AuditAction {
  LOGIN = 'LOGIN',
  REGISTER = 'REGISTER',
  LOGOUT = 'LOGOUT',
  EMAIL_CONFIRMED = 'EMAIL_CONFIRMED',
  FAILED_LOGIN = 'FAILED_LOGIN',
  PASSWORD_RESET_REQUEST = 'PASSWORD_RESET_REQUEST',
  PASSWORD_RESET = 'PASSWORD_RESET',
  ROLE_CHANGE = 'ROLE_CHANGE',
  USER_DELETED = 'USER_DELETED',
  UNBAN_USER = 'UNBAN_USER',
  INVITE_SENT = 'INVITE_SENT',
  INVITE_ACCEPTED = 'INVITE_ACCEPTED',
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
  action!: AuditAction;

  @Prop({
    type: MongooseSchema.Types.ObjectId,
    ref: 'User',
    required: false,
  })
  userId?: string; // Utilisateur qui fait l'action

  @Prop({ required: true })
  userEmail!: string;

  @Prop({ required: true })
  userRole!: string;

  @Prop({ type: Object })
  details!: Record<string, unknown>; // Détails supplémentaires dynamiques

  @Prop()
  target?: string; // Who/what was the target of the action (email, business name, etc.)

  @Prop()
  ipAddress?: string;

  createdAt!: Date;
  updatedAt!: Date;
}

export const AuditLogSchema = SchemaFactory.createForClass(AuditLog);

// Indexing pour optimiser la recherche par un Compliance Officer
AuditLogSchema.index({ action: 1, createdAt: -1 });
AuditLogSchema.index({ createdAt: -1 });
// Helpful indexes for auditing queries by actor/target
AuditLogSchema.index({ userId: 1, createdAt: -1 });
AuditLogSchema.index({ userEmail: 1, createdAt: -1 });
AuditLogSchema.index({ userRole: 1, createdAt: -1 });
AuditLogSchema.index({ target: 1, createdAt: -1 });
