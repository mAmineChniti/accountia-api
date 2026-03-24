import {
  Controller,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { EmailService } from '@/email/email.service';
import { SendEmailDto, SendEmailResponseDto } from '@/email/dto/send-email.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { Role } from '@/auth/enums/role.enum';

@ApiTags('Email')
@Controller('email')
export class EmailController {
  constructor(private readonly emailService: EmailService) {}

  @Post('send')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(
    Role.PLATFORM_ADMIN,
    Role.PLATFORM_OWNER,
    Role.BUSINESS_ADMIN,
    Role.BUSINESS_OWNER
  )
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Send email notification',
    description:
      'Send an email to a recipient with the specified content. Typically used for business application approval/rejection notifications.',
  })
  @ApiResponse({
    status: 200,
    description: 'Email sent successfully',
    type: SendEmailResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request body',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - authentication required',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - insufficient permissions',
  })
  @ApiResponse({
    status: 500,
    description: 'Email service error',
  })
  async sendEmail(
    @Body() sendEmailDto: SendEmailDto
  ): Promise<SendEmailResponseDto> {
    return this.emailService.sendEmail(sendEmailDto);
  }

  @Post('test')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Send test email',
    description: 'Send a test email to verify email service configuration',
  })
  @ApiResponse({
    status: 200,
    description: 'Test email sent successfully',
    type: SendEmailResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - authentication required',
  })
  async sendTestEmail(@Body('to') to: string): Promise<SendEmailResponseDto> {
    return this.emailService.testEmail(to);
  }
}
