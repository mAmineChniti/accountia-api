import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { ApiProperty } from '@nestjs/swagger';

export type TemplateDocument = Template & Document;

@Schema({ collection: 'invoice_templates', timestamps: true })
export class Template {
  @ApiProperty({ example: 'Professional' })
  @Prop({ required: true })
  name: string;

  @ApiProperty({ example: 'standard' })
  @Prop({ required: true, unique: true })
  key: string;

  @ApiProperty({ example: 'A clean and professional template' })
  @Prop()
  description: string;
}

export const TemplateSchema = SchemaFactory.createForClass(Template);
