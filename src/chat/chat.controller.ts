import { Controller, Get, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';

@ApiTags('Chat')
@Controller('chat')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
@ApiResponse({
  status: 401,
  description: 'Unauthorized - Invalid or missing JWT token',
})
export class ChatController {
  @Get('status')
  @ApiOperation({
    summary: 'Chat WebSocket status',
    description:
      'Returns Socket.IO connection info. Use the Socket.IO client library to connect with JWT token in auth.token.',
  })
  @ApiResponse({
    status: 200,
    description: 'Socket.IO endpoint info',
    schema: {
      properties: {
        path: { type: 'string' },
        namespace: { type: 'string' },
        transport: { type: 'array', items: { type: 'string' } },
        events: { type: 'object' },
      },
    },
  })
  getStatus(): {
    path: string;
    namespace: string;
    transport: string[];
    events: Record<string, string>;
  } {
    return {
      path: '/socket.io/',
      namespace: '/chat',
      transport: ['websocket', 'polling'],
      events: {
        connect: 'Send JWT token in auth.token (Socket.IO handshake)',
        chat_message: 'Send: { query, businessId?, history?[], messageId? }',
        message_start: 'Streaming started',
        message_chunk: 'Response text chunk (streamed from Groq)',
        message_complete: 'Full response received',
        message_error: 'Error occurred',
      },
    };
  }
}
