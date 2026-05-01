import {
  IsString,
  IsOptional,
  IsEnum,
  IsArray,
  IsBoolean,
  IsDate,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { CommentEntityType } from '../schemas/comment.schema';

export class CreateCommentDto {
  @ApiProperty({ description: 'Business ID for tenant resolution' })
  @IsString()
  businessId!: string;

  @ApiProperty({ enum: CommentEntityType })
  @IsEnum(CommentEntityType)
  entityType!: CommentEntityType;

  @ApiProperty({ description: 'ID of the entity being commented on' })
  @IsString()
  entityId!: string;

  @ApiProperty({ description: 'Comment text body' })
  @IsString()
  body!: string;

  @ApiPropertyOptional({ description: 'Parent comment ID for threading' })
  @IsOptional()
  @IsString()
  parentId?: string;

  @ApiPropertyOptional({
    type: [String],
    description: 'User IDs mentioned with @',
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  mentions?: string[];
}

export class UpdateCommentDto {
  @ApiProperty({ description: 'Business ID for tenant resolution' })
  @IsString()
  businessId!: string;

  @ApiProperty({ description: 'Updated comment body' })
  @IsString()
  body!: string;
}

export class DeleteCommentDto {
  @ApiProperty({ description: 'Business ID for tenant resolution' })
  @IsString()
  businessId!: string;
}

export class CommentResponseDto {
  @IsString()
  id!: string;

  @IsString()
  businessId!: string;

  @IsEnum(CommentEntityType)
  entityType!: CommentEntityType;

  @IsString()
  entityId!: string;

  @IsString()
  authorId!: string;

  @IsString()
  authorName!: string;

  @IsString()
  body!: string;

  @IsOptional()
  @IsString()
  parentId?: string | null;

  @IsArray()
  mentions!: string[];

  @IsBoolean()
  isEdited!: boolean;

  @IsBoolean()
  isDeleted!: boolean;

  @IsDate()
  @Type(() => Date)
  createdAt!: Date;

  @IsDate()
  @Type(() => Date)
  updatedAt!: Date;
}

export class CommentListResponseDto {
  @IsArray()
  comments!: CommentResponseDto[];

  @IsString()
  entityId!: string;

  @IsEnum(CommentEntityType)
  entityType!: CommentEntityType;
}
