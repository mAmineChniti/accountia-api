import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import {
  Comment,
  CommentEntityType,
  CommentSchema,
} from './schemas/comment.schema';
import {
  CreateCommentDto,
  UpdateCommentDto,
  CommentResponseDto,
  CommentListResponseDto,
} from './dto/comment.dto';

@Injectable()
export class CommentsService {
  constructor(@InjectConnection() private connection: Connection) {}

  private getCommentModel(databaseName: string): Model<Comment> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try {
      return tenantDb.model<Comment>(Comment.name);
    } catch {
      return tenantDb.model<Comment>(Comment.name, CommentSchema);
    }
  }

  async create(
    businessId: string,
    databaseName: string,
    dto: CreateCommentDto,
    userId: string,
    authorName: string
  ): Promise<CommentResponseDto> {
    const model = this.getCommentModel(databaseName);
    const { businessId: _, ...data } = dto;
    void _;

    const comment = new model({
      businessId,
      ...data,
      authorId: userId,
      authorName,
      isEdited: false,
      isDeleted: false,
    });
    await comment.save();
    return this.formatResponse(comment);
  }

  async findByEntity(
    businessId: string,
    databaseName: string,
    entityType: CommentEntityType,
    entityId: string
  ): Promise<CommentListResponseDto> {
    const model = this.getCommentModel(databaseName);
    const comments = await model
      .find({ businessId, entityType, entityId, isDeleted: false })
      .sort({ createdAt: 1 })
      .lean();

    return {
      entityId,
      entityType,
      comments: (comments as Comment[]).map((c) => this.formatResponse(c)),
    };
  }

  async update(
    id: string,
    businessId: string,
    databaseName: string,
    dto: UpdateCommentDto,
    userId: string
  ): Promise<CommentResponseDto> {
    const model = this.getCommentModel(databaseName);
    const comment = await model.findById(id);

    if (!comment || comment.isDeleted) {
      throw new NotFoundException('Comment not found');
    }
    if (String(comment.businessId) !== businessId) {
      throw new ForbiddenException('Access denied');
    }
    if (String(comment.authorId) !== userId) {
      throw new ForbiddenException('You can only edit your own comments');
    }

    comment.body = dto.body;
    comment.isEdited = true;
    await comment.save();
    return this.formatResponse(comment);
  }

  async delete(
    id: string,
    businessId: string,
    databaseName: string,
    userId: string,
    isAdmin: boolean
  ): Promise<void> {
    const model = this.getCommentModel(databaseName);
    const comment = await model.findById(id);

    if (!comment || comment.isDeleted) {
      throw new NotFoundException('Comment not found');
    }
    if (String(comment.businessId) !== businessId) {
      throw new ForbiddenException('Access denied');
    }
    if (!isAdmin && String(comment.authorId) !== userId) {
      throw new ForbiddenException('You can only delete your own comments');
    }

    comment.isDeleted = true;
    comment.body = '[deleted]';
    await comment.save();
  }

  private formatResponse(comment: Comment): CommentResponseDto {
    return {
      id: String(comment._id),
      businessId: String(comment.businessId),
      entityType: comment.entityType,
      entityId: String(comment.entityId),
      authorId: String(comment.authorId),
      authorName: comment.authorName,
      body: comment.body,
      parentId: comment.parentId ? String(comment.parentId) : null,
      mentions: comment.mentions ?? [],
      isEdited: comment.isEdited,
      isDeleted: comment.isDeleted,
      createdAt: comment.createdAt,
      updatedAt: comment.updatedAt,
    };
  }
}
