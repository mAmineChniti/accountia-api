import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ChatService } from './chat.service';
import { User } from '@/users/schemas/user.schema';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { WebSocketStateService } from '@/redis/websocket-state.service';

interface ChatMessage {
  query: string;
  businessId?: string;
  history?: Array<{ role: string; content: string }>;
  messageId?: string; // Client-generated ID for tracking
}

interface AuthenticatedSocket extends Socket {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

@WebSocketGateway({
  namespace: 'chat',
  cors: {
    origin: (origin, callback) => {
      // Get origins from ConfigService at runtime for validated config
      // Supports comma-separated FRONTEND_URLS for multiple production origins
      const frontendUrls =
        process.env.FRONTEND_URLS ??
        process.env.FRONTEND_URL ??
        'http://localhost:3000';
      const allowed = frontendUrls.split(',').map((url) => url.trim());
      // Always allow localhost for development
      allowed.push('http://localhost:3000', 'http://localhost:3001');

      // Allow requests with no origin (e.g., mobile apps, Postman)
      if (!origin || allowed.includes(origin)) {
        // eslint-disable-next-line unicorn/no-null -- Socket.IO CORS callback type requires null
        callback(null, true);
      } else {
        callback(new Error('Origin not allowed by CORS'), false);
      }
    },
    credentials: true,
  },
  transports: ['websocket', 'polling'],
  pingInterval: 10_000,
  pingTimeout: 5000,
})
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(ChatGateway.name);

  constructor(
    private readonly chatService: ChatService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly wsStateService: WebSocketStateService,
    @InjectModel(User.name) private readonly userModel: Model<User>
  ) {}

  async handleConnection(client: AuthenticatedSocket) {
    try {
      // Only accept token from auth (not query) to prevent JWT logging in URLs
      const token = client.handshake.auth.token as string | undefined;

      if (!token || typeof token !== 'string') {
        this.logger.warn('Client connected without token');
        client.disconnect(true);
        return;
      }

      const secret = this.configService.get<string>('JWT_SECRET');
      if (!secret) {
        this.logger.error('JWT_SECRET not configured');
        client.disconnect(true);
        return;
      }

      const payload = this.jwtService.verify<{ sub: string }>(token, {
        secret,
      });

      const user = await this.userModel
        .findById(payload.sub, { email: 1, role: 1 })
        .lean();
      if (!user) {
        this.logger.warn('User from token not found');
        client.disconnect(true);
        return;
      }

      client.user = {
        id: payload.sub,
        email: user.email,
        role: user.role,
      };

      // Record connection in Redis for tracking
      void this.wsStateService.recordConnection(client.id, client.user.id, {
        email: client.user.email,
        role: client.user.role,
        ip: client.handshake.address,
      });

      this.logger.debug(`Client connected: ${client.user.id}`);
      client.emit('connected', { status: 'connected', userId: client.user.id });
    } catch {
      this.logger.warn('Authentication failed, disconnecting client');
      client.disconnect(true);
    }
  }

  handleDisconnect(client: AuthenticatedSocket) {
    this.logger.debug(`Client disconnected: ${client.user?.id ?? 'unknown'}`);
    // Remove connection from Redis
    void this.wsStateService.recordDisconnection(client.id);
  }

  @SubscribeMessage('chat_message')
  async handleChatMessage(
    @MessageBody() data: ChatMessage,
    @ConnectedSocket() client: AuthenticatedSocket
  ): Promise<void> {
    if (!client.user) {
      client.emit('message_error', {
        messageId: data.messageId,
        message: 'Not authenticated',
      });
      return;
    }

    const { query, businessId, history = [], messageId } = data;

    if (!query || typeof query !== 'string') {
      client.emit('message_error', { messageId, message: 'Query is required' });
      return;
    }

    const startTime = Date.now();

    // Send start event immediately
    client.emit('message_start', {
      messageId,
      timestamp: new Date().toISOString(),
    });

    try {
      // Use volatile emit for chunks to prioritize speed over guaranteed delivery
      // This prevents buffering if client is slow to receive
      await this.chatService.streamAiResponse(
        client.user.id,
        query,
        businessId ?? undefined,
        client.user.email,
        history,
        {
          onChunk: (chunk: string) => {
            // Use reliable emit for chunks so clients don't lose data
            // (client can still reconcile with fullResponse from message_complete)
            client.emit('message_chunk', {
              messageId,
              chunk,
            });
          },
          onComplete: (fullResponse: string) => {
            const duration = Date.now() - startTime;
            this.logger.debug(
              `Response completed in ${duration}ms for user ${client.user?.id}`
            );

            client.emit('message_complete', {
              messageId,
              response: fullResponse,
              duration,
              timestamp: new Date().toISOString(),
            });
          },
          onError: (error: Error) => {
            this.logger.error('Streaming error:', error.message);
            client.emit('message_error', {
              messageId,
              message: error.message || 'An error occurred',
            });
          },
        }
      );
    } catch (error) {
      this.logger.error('Chat error:', error);
      const message =
        error instanceof Error ? error.message : 'An error occurred';
      client.emit('message_error', { messageId, message });
    }
  }

  @SubscribeMessage('ping')
  handlePing(@ConnectedSocket() client: Socket): void {
    // Update last ping time in Redis to keep connection alive
    void this.wsStateService.recordPing(client.id);
    client.emit('pong', { timestamp: Date.now() });
  }
}
