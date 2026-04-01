import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { ChatService } from './chat.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { type UserPayload } from '../auth/types/auth.types';

@ApiTags('Chat')
@Controller('chat')
export class ChatController {
  constructor(private readonly chatService: ChatService) {}

  @UseGuards(JwtAuthGuard)
  @Post('message')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Send a chat message' })
  @ApiResponse({
    status: 200,
    description: 'Chat message processed',
  })
  async handleMessage(
    @Body()
    body: {
      query: string;
      context?: string; // used for role override
      systemContext?: Record<string, unknown>; // used for passing data like financial stats
      history?: Array<{ role: string; content: string }>;
    },
    @CurrentUser() user: UserPayload
  ): Promise<unknown> {
    const roleContext = body.context ?? user.role;
    const history = body.history ?? [];
    return this.chatService.getAiResponse(
      roleContext,
      body.query,
      history,
      body.systemContext
    );
  }
}
