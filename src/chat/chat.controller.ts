import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { ChatService } from './chat.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

@Controller('chat')
export class ChatController {
  constructor(private readonly chatService: ChatService) {}

  @UseGuards(JwtAuthGuard)
  @Post('message')
  async handleMessage(
    @Body() body: {
      query: string;
      context?: string;
      history?: Array<{ role: string; content: string }>;
    },
    @CurrentUser() user: any,
  ) {
    const roleContext = body.context || user.role;
    const history = body.history || [];
    return this.chatService.getAiResponse(roleContext, body.query, history);
  }
}
