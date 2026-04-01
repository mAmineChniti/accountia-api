import {
  Controller,
  Get,
  Patch,
  Param,
  Sse,
  UseGuards,
  MessageEvent,
  Query,
  UnauthorizedException,
  Req,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtService } from '@nestjs/jwt';
import { ApiBearerAuth, ApiTags, ApiOkResponse } from '@nestjs/swagger';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, type UserDocument } from '@/users/schemas/user.schema';
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
  constructor(
    private readonly notificationsService: NotificationsService,
    private readonly jwtService: JwtService,
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>
  ) {}

  /**
   * SSE stream: browser EventSource can't set custom headers,
   * so we accept the token as a query param instead.
   */
  @Sse('sse')
  async stream(
    @Query('token') tokenParam?: string,
    @Query('businessId') businessIdParam?: string
  ): Promise<Observable<MessageEvent>> {
    if (!tokenParam) {
      throw new UnauthorizedException('Missing token');
    }

    let payload: { sub?: string };
    try {
      payload = this.jwtService.verify<{ sub?: string }>(tokenParam);
    } catch {
      throw new UnauthorizedException('Invalid token');
    }

    const user = await this.userModel.findById(payload.sub).lean();
    if (!user) throw new UnauthorizedException('User not found');

    // Admins, Business Owners, or Clients
    const allowedRoles = [
      Role.PLATFORM_OWNER,
      Role.PLATFORM_ADMIN,
      Role.BUSINESS_OWNER,
      Role.BUSINESS_ADMIN,
      Role.CLIENT,
    ];
    if (!allowedRoles.includes(user.role)) {
      throw new UnauthorizedException('Insufficient role');
    }

    const isBusinessOwner = [Role.BUSINESS_OWNER, Role.BUSINESS_ADMIN].includes(
      user.role
    );
    const isClient = user.role === Role.CLIENT;

    return this.notificationsService.getEventStream(
      isBusinessOwner ? (businessIdParam ?? undefined) : undefined,
      isClient ? user.email : undefined
    );
  }

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(
    Role.PLATFORM_OWNER,
    Role.PLATFORM_ADMIN,
    Role.BUSINESS_OWNER,
    Role.BUSINESS_ADMIN,
    Role.CLIENT
  )
  @ApiOkResponse()
  async getRecent(
    @Req() req: { user: UserPayload },
    @Query('businessId') businessId?: string
  ) {
    const userRole = req.user.role;
    const userEmail = req.user.email;

    const isClient = userRole === Role.CLIENT;
    const filterEmail = isClient ? userEmail : undefined;
    const filterBusinessId = isClient ? undefined : businessId;

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
  @Roles(
    Role.PLATFORM_OWNER,
    Role.PLATFORM_ADMIN,
    Role.BUSINESS_OWNER,
    Role.BUSINESS_ADMIN,
    Role.CLIENT
  )
  @ApiOkResponse()
  async markAsRead(@Param('id') id: string) {
    await this.notificationsService.markAsRead(id);
    return { message: 'Notification marked as read' };
  }

  @Patch('read-all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(
    Role.PLATFORM_OWNER,
    Role.PLATFORM_ADMIN,
    Role.BUSINESS_OWNER,
    Role.BUSINESS_ADMIN,
    Role.CLIENT
  )
  @ApiOkResponse()
  async markAllAsRead(
    @Req() req: { user: UserPayload },
    @Query('businessId') businessId?: string
  ) {
    const userRole = req.user.role;
    const userEmail = req.user.email;

    const isClient = userRole === Role.CLIENT;
    const filterEmail = isClient ? userEmail : undefined;
    const filterBusinessId = isClient ? undefined : businessId;

    await this.notificationsService.markAllAsRead(
      filterBusinessId,
      filterEmail
    );
    return { message: 'All notifications marked as read' };
  }
}
