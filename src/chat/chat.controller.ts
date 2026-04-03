import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { ChatService, type AiResponse } from './chat.service';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';

@ApiTags('Chat')
@Controller('chat')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
@ApiResponse({
  status: 401,
  description: 'Unauthorized - Invalid or missing JWT token',
})
@ApiResponse({
  status: 403,
  description: 'Forbidden - You do not have access to this business',
})
@ApiResponse({ status: 500, description: 'Internal Server Error' })
export class ChatController {
  constructor(private readonly chatService: ChatService) {}

  @Post('message')
  @ApiOperation({
    summary: 'Send a chat message to AI assistant',
    description:
      'Process a user message for a specific business. The AI uses Gemini API with contextual prompts based on user role and automatically fetches business statistics.',
  })
  @ApiResponse({
    status: 200,
    description: 'Chat message processed successfully',
    schema: {
      properties: {
        response: { type: 'string' },
        choices: { type: 'array', items: { type: 'string' } },
        link: {
          type: 'object',
          properties: {
            text: { type: 'string' },
            url: { type: 'string' },
          },
          nullable: true,
        },
        type: { type: 'string', enum: ['text', 'choices', 'analysis'] },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid input',
  })
  async handleMessage(
    @Body()
    body: {
      businessId: string;
      query: string;
      history?: Array<{ role: string; content: string }>;
    },
    @CurrentUser() user: UserPayload
  ): Promise<AiResponse> {
    return this.chatService.getAiResponse(
      user.id,
      user.role,
      body.query,
      body.businessId,
      body.history ?? []
    );
  }
}
