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
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtService } from '@nestjs/jwt';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, type UserDocument } from '@/users/schemas/user.schema';
import { NotificationsService } from './notifications.service';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { Role } from '@/auth/enums/role.enum';

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
  async stream(@Query('token') tokenParam?: string): Promise<Observable<MessageEvent>> {
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
    if (!user || (user.role !== Role.PLATFORM_OWNER && user.role !== Role.PLATFORM_ADMIN)) {
      throw new UnauthorizedException('Insufficient role');
    }

    return this.notificationsService.getEventStream();
  }

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  async getRecent() {
    const notifications = await this.notificationsService.getRecent();
    return {
      notifications: notifications.map((n: any) => ({
        id: n._id.toString(),
        type: n.type,
        message: n.message,
        payload: n.payload,
        isRead: n.isRead,
        createdAt: n.createdAt,
      })),
      unreadCount: notifications.filter((n: any) => !n.isRead).length,
    };
  }

  @Patch(':id/read')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  async markAsRead(@Param('id') id: string) {
    await this.notificationsService.markAsRead(id);
    return { message: 'Notification marked as read' };
  }

  @Patch('read-all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  async markAllAsRead() {
    await this.notificationsService.markAllAsRead();
    return { message: 'All notifications marked as read' };
  }
}
