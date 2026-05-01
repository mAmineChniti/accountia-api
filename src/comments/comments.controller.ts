import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiBearerAuth,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { CommentsService } from './comments.service';
import {
  CreateCommentDto,
  UpdateCommentDto,
  DeleteCommentDto,
  CommentResponseDto,
  CommentListResponseDto,
} from './dto/comment.dto';
import { CommentEntityType } from './schemas/comment.schema';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import {
  BusinessRolesGuard,
  BusinessRoles,
} from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';
import type { UserPayload } from '@/auth/types/auth.types';

@ApiTags('Comments')
@Controller('comments')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(
  BusinessUserRole.OWNER,
  BusinessUserRole.ADMIN,
  BusinessUserRole.MEMBER
)
export class CommentsController {
  constructor(private readonly commentsService: CommentsService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Add a comment to an entity (invoice, expense, PO)',
  })
  @ApiCreatedResponse({ type: CommentResponseDto })
  async create(
    @Body() dto: CreateCommentDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<CommentResponseDto> {
    const authorName =
      `${user.firstName} ${user.lastName}`.trim() || user.username;
    return this.commentsService.create(
      tenant.businessId,
      tenant.databaseName,
      dto,
      user.id,
      authorName
    );
  }

  @Get()
  @ApiOperation({ summary: 'Get all comments for an entity' })
  @ApiOkResponse({ type: CommentListResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiQuery({ name: 'entityType', required: true, enum: CommentEntityType })
  @ApiQuery({ name: 'entityId', required: true, type: String })
  async findByEntity(
    @CurrentTenant() tenant: TenantContext,
    @Query('entityType') entityType: CommentEntityType,
    @Query('entityId') entityId: string
  ): Promise<CommentListResponseDto> {
    return this.commentsService.findByEntity(
      tenant.businessId,
      tenant.databaseName,
      entityType,
      entityId
    );
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Edit a comment (author only)' })
  @ApiOkResponse({ type: CommentResponseDto })
  @ApiParam({ name: 'id', type: String })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateCommentDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<CommentResponseDto> {
    return this.commentsService.update(
      id,
      tenant.businessId,
      tenant.databaseName,
      dto,
      user.id
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a comment (author or admin)' })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async delete(
    @Param('id') id: string,
    @Body() dto: DeleteCommentDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<void> {
    void dto;
    const isAdmin = false;
    return this.commentsService.delete(
      id,
      tenant.businessId,
      tenant.databaseName,
      user.id,
      isAdmin
    );
  }
}
