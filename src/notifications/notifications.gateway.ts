import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
} from '@nestjs/websockets';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Server, Socket } from 'socket.io';
import { User } from '@/users/schemas/user.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { Role } from '@/auth/enums/role.enum';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import type { NotificationEvent } from './notifications.service';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  userRole?: Role;
  userEmail?: string;
  businessId?: string;
}

/**
 * WebSocket Gateway for real-time notifications.
 *
 * Features:
 * - JWT authentication via query parameter (token)
 * - Role-based notification filtering
 * - Room-based isolation (platform admin, business, or client)
 * - Automatic reconnection handling via socket.io
 * - Proper cleanup on disconnect
 *
 * Client Usage:
 * ```typescript
 * // For individual client notifications
 * const socket = io('http://localhost:3000', {
 *   query: { token: 'your-jwt-token' },
 *   autoConnect: true,
 * });
 *
 * // For business team notifications
 * const socket = io('http://localhost:3000', {
 *   query: { token: 'your-jwt-token', businessId: 'business-id' },
 *   autoConnect: true,
 * });
 *
 * socket.on('notification', (data) => {
 *   console.log('New notification:', data);
 * });
 *
 * socket.on('connect_error', (error) => {
 *   console.error('Connection failed:', error.message);
 * });
 * ```
 *
 * Rooms:
 * - 'admin' - Platform owner/admin notifications
 * - 'business:{businessId}' - Business team notifications (all owner/admin members)
 * - 'client:{email}' - Individual client notifications
 */
@Injectable()
@WebSocketGateway({
  cors: {
    origin: process.env.FRONTEND_URL ?? 'http://localhost:3000',
    credentials: true,
  },
})
export class NotificationsGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server!: Server;

  constructor(
    private readonly jwtService: JwtService,
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(BusinessUser.name)
    private readonly businessUserModel: Model<BusinessUser>
  ) {}

  afterInit(server: Server) {
    // Set up middleware to authenticate before connection
    server.use((socket: AuthenticatedSocket, next) => {
      const token = socket.handshake.query.token as string;
      const businessId = socket.handshake.query.businessId as string;

      if (!token) {
        return next(new UnauthorizedException('Missing token'));
      }

      this.validateAndAttachUser(socket, token, businessId)
        .then(() => next())
        .catch((error: unknown) => {
          next(error instanceof Error ? error : new Error(String(error)));
        });
    });
  }

  private async validateAndAttachUser(
    socket: AuthenticatedSocket,
    token: string,
    businessId: string
  ): Promise<void> {
    try {
      const payload = this.jwtService.verify<{ sub?: string }>(token);
      const user = await this.userModel.findById(payload.sub).lean();

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Allowed roles
      const allowedRoles = [
        Role.PLATFORM_OWNER,
        Role.PLATFORM_ADMIN,
        Role.CLIENT,
      ];

      if (!allowedRoles.includes(user.role)) {
        throw new UnauthorizedException('Insufficient role');
      }

      // Attach user info to socket
      socket.userId = payload.sub;
      socket.userRole = user.role;
      socket.userEmail = user.email;
      socket.businessId = businessId;
    } catch (error) {
      throw error instanceof UnauthorizedException
        ? error
        : new UnauthorizedException('Invalid token');
    }
  }

  handleConnection(socket: AuthenticatedSocket) {
    // Join user to appropriate room based on role
    const isAdmin = [Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN].includes(
      socket.userRole!
    );
    const isClient = socket.userRole === Role.CLIENT;

    if (isAdmin) {
      void socket.join('admin');
    } else if (isClient) {
      void socket.join(`client:${socket.userEmail}`);
    }

    // Join business room if businessId is provided
    if (socket.businessId) {
      this.joinBusinessRoom(socket).catch((error) => {
        console.error('Error joining business room:', error);
      });
    }
  }

  private async joinBusinessRoom(socket: AuthenticatedSocket): Promise<void> {
    try {
      // Check if user is admin/owner in this business
      const businessUser = await this.businessUserModel
        .findOne({
          businessId: socket.businessId,
          userId: socket.userId,
          role: { $in: [BusinessUserRole.OWNER, BusinessUserRole.ADMIN] },
        })
        .lean();

      if (businessUser) {
        // Join business-specific room
        await socket.join(`business:${socket.businessId}`);
      }
    } catch (error) {
      console.error('Error joining business room:', error);
    }
  }

  handleDisconnect() {
    // Socket automatically leaves all rooms on disconnect
    // No additional cleanup needed
  }

  /**
   * Client can subscribe to specific notification types.
   * Useful for filtering notifications client-side.
   */
  @SubscribeMessage('subscribe')
  handleSubscribe(
    socket: AuthenticatedSocket,
    data: { types?: string[] }
  ): { success: boolean; message: string } {
    const types = Array.isArray(data.types) ? data.types : [];
    socket.data ??= {};
    (socket.data as Record<string, unknown>).subscribedTypes = types;
    return {
      success: true,
      message: `Subscribed to types: ${types.join(', ') || 'all'}`,
    };
  }

  /**
   * Emit notification to appropriate room.
   * Called by NotificationsService.
   */
  emitNotification(event: NotificationEvent) {
    const notification = {
      id: event.id,
      type: event.type,
      message: event.message,
      payload: event.payload,
      createdAt: event.createdAt,
    };

    // Route notification to appropriate room
    if (event.targetBusinessId) {
      this.server
        .to(`business:${event.targetBusinessId}`)
        .emit('notification', notification);
    } else if (event.targetUserEmail) {
      this.server
        .to(`client:${event.targetUserEmail}`)
        .emit('notification', notification);
    } else {
      // Global notification for admins
      this.server.to('admin').emit('notification', notification);
    }
  }

  /**
   * Get count of active connections per room.
   * Useful for debugging/monitoring.
   */
  getConnectionStats() {
    const rooms = this.server.sockets.adapter.rooms;
    const stats: Record<string, number> = {};

    for (const [room, sockets] of rooms) {
      if (!room.startsWith('/')) {
        // Skip socket IDs
        stats[room] = sockets.size;
      }
    }

    return stats;
  }
}
