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
      'Returns WebSocket endpoint info. Connect to ws://host/chat with JWT token for real-time streaming chat.',
  })
  @ApiResponse({
    status: 200,
    description: 'WebSocket endpoint info',
    schema: {
      properties: {
        websocket: { type: 'string' },
        namespace: { type: 'string' },
        events: { type: 'object' },
      },
    },
  })
  getStatus(): {
    websocket: string;
    namespace: string;
    events: Record<string, string>;
  } {
    return {
      websocket: 'ws://host/chat',
      namespace: '/chat',
      events: {
        connect: 'Send JWT token in auth.token or query.token',
        chat_message: 'Send: { query, businessId?, history?[] }',
        message_start: 'Streaming started',
        message_chunk: 'Response text chunk (streamed from Groq)',
        message_complete: 'Full response received',
        message_error: 'Error occurred',
      },
    };
  }
}
