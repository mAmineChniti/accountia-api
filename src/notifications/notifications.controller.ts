import {
  Controller,
  Get,
  Patch,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiTags,
  ApiOkResponse,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { NotificationsService } from './notifications.service';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { Role } from '@/auth/enums/role.enum';
import type { UserPayload } from '@/auth/types/auth.types';

@ApiTags('Notifications')
@Controller('notifications')
@ApiBearerAuth()
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN, Role.CLIENT)
  @ApiOperation({
    summary: 'Get recent notifications',
    description:
      'Retrieve up to 20 most recent notifications. Filtered by user role and context.',
  })
  @ApiQuery({
    name: 'businessId',
    type: 'string',
    description: 'Business ID for business owner notifications filter',
    required: false,
  })
  @ApiOkResponse({
    description: 'List of notifications with unread count',
    schema: {
      example: {
        notifications: [
          {
            id: '507f1f77bcf86cd799439011',
            type: 'invoice.sent',
            message: 'Invoice sent to client',
            payload: { invoiceId: '507f1f77bcf86cd799439012' },
            isRead: false,
            createdAt: '2026-04-02T10:00:00Z',
          },
        ],
        unreadCount: 1,
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Insufficient role' })
  async getRecent(
    @Req() req: { user: UserPayload },
    @Query('businessId') businessId?: string
  ) {
    const userRole = req.user.role;
    const userEmail = req.user.email;

    const isClient = userRole === Role.CLIENT;
    const filterBusinessId = businessId?.trim() ?? undefined;
    const filterEmail =
      !filterBusinessId && isClient
        ? (userEmail?.trim() ?? undefined)
        : undefined;

    const notifications = await this.notificationsService.getRecent(
      filterBusinessId,
      filterEmail
    );
    return {
      notifications: notifications.map((notification) => ({
        id: notification._id.toString(),
        type: notification.type,
        message: notification.message,
        payload: notification.payload,
        isRead: notification.isRead,
        createdAt: notification.createdAt,
      })),
      unreadCount: notifications.filter((notification) => !notification.isRead)
        .length,
    };
  }

  @Patch(':id/read')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN, Role.CLIENT)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Mark notification as read',
    description: 'Update a specific notification to read status.',
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    description: 'Notification MongoDB ID',
  })
  @ApiOkResponse({
    description: 'Notification marked as read',
    schema: { example: { message: 'Notification marked as read' } },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Insufficient role' })
  @ApiResponse({ status: 404, description: 'Notification not found' })
  async markAsRead(@Param('id') id: string) {
    await this.notificationsService.markAsRead(id);
    return { message: 'Notification marked as read' };
  }

  @Patch('read-all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN, Role.CLIENT)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Mark all notifications as read',
    description:
      'Bulk update all unread notifications to read status, filtered by user context.',
  })
  @ApiQuery({
    name: 'businessId',
    type: 'string',
    description: 'Business ID for business owner context',
    required: false,
  })
  @ApiOkResponse({
    description: 'All notifications marked as read',
    schema: { example: { message: 'All notifications marked as read' } },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Insufficient role' })
  async markAllAsRead(
    @Req() req: { user: UserPayload },
    @Query('businessId') businessId?: string
  ) {
    const userRole = req.user.role;
    const userEmail = req.user.email;

    const isClient = userRole === Role.CLIENT;
    const filterBusinessId = businessId?.trim() ?? undefined;
    const filterEmail =
      !filterBusinessId && isClient
        ? (userEmail?.trim() ?? undefined)
        : undefined;

    await this.notificationsService.markAllAsRead(
      filterBusinessId,
      filterEmail
    );
    return { message: 'All notifications marked as read' };
  }
}
