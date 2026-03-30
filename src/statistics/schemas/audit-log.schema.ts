import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { ApiProperty } from '@nestjs/swagger';

export type AuditLogDocument = AuditLog & Document;

@Schema({ collection: 'audit_logs', timestamps: true })
export class AuditLog {
  @ApiProperty({ example: 'user123' })
  @Prop({ required: true })
  userId: string;

  @ApiProperty({ example: 'admin_john' })
  @Prop({ required: true })
  username: string;

  @ApiProperty({ example: 'UPDATE', enum: ['CREATE', 'UPDATE', 'DELETE', 'LOGIN', 'APPROVE', 'REJECT'] })
  @Prop({ required: true })
  action: string;

  @ApiProperty({ example: 'User' })
  @Prop({ required: true })
  resource: string;

  @ApiProperty({ example: { oldRole: 'CLIENT', newRole: 'ADMIN' } })
  @Prop({ type: Object })
  details: any;

  @Prop()
  createdAt: Date;
}

export const AuditLogSchema = SchemaFactory.createForClass(AuditLog);
