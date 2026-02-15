import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Get,
  Put,
  Patch,
  Delete,
  Req,
  Param,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import type { Request } from 'express';
import { AuthService } from '@/auth/auth.service';
import { RegisterDto } from '@/auth/dto/register.dto';
import { LoginDto } from '@/auth/dto/login.dto';
import { ForgotPasswordDto } from '@/auth/dto/forgot-password.dto';
import { ResetPasswordDto } from '@/auth/dto/reset-password.dto';
import { UpdateUserDto } from '@/auth/dto/update-user.dto';
import { FetchUserByIdDto } from '@/auth/dto/fetch-user-by-id.dto';
import { AuthResponseDto } from '@/auth/dto/auth-response.dto';
import {
  UserResponseDto,
  MessageResponseDto,
  HealthResponseDto,
} from '@/auth/dto/user-response.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RefreshJwtGuard } from '@/auth/guards/refresh-jwt.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';

@ApiTags('Authentication')
@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 201,
    description: 'User successfully registered',
    type: AuthResponseDto,
  })
  @ApiResponse({ status: 409, description: 'User already exists' })
  async register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
    return this.authService.register(registerDto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: AuthResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 403, description: 'Account locked or deactivated' })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request
  ): Promise<AuthResponseDto> {
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    return this.authService.login(loginDto, ip);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout user' })
  @ApiResponse({ status: 200, description: 'Logout successful' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logout(
    @CurrentUser() user: UserPayload,
    @Body() body: RefreshTokenDto
  ): Promise<void> {
    await this.authService.logout(user.id, body.refreshToken);
  }

  @Post('refresh')
  @UseGuards(RefreshJwtGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Refresh authentication tokens' })
  @ApiResponse({
    status: 200,
    description: 'Tokens refreshed successfully',
    type: AuthResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async refreshTokenHandler(
    @CurrentUser() user: UserPayload
  ): Promise<AuthResponseDto> {
    const tokens = this.authService.generateTokens(user);

    await this.authService.updateRefreshToken(user.id, tokens.refreshToken);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
      },
    };
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({ status: 200, description: 'Password reset email sent' })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto
  ): Promise<void> {
    await this.authService.forgotPassword(forgotPasswordDto);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password' })
  @ApiResponse({ status: 200, description: 'Password reset successful' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto
  ): Promise<void> {
    await this.authService.resetPassword(resetPasswordDto);
  }

  @Get('confirm-email/:token')
  @ApiOperation({ summary: 'Confirm email address' })
  @ApiResponse({ status: 200, description: 'Email confirmed successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  async confirmEmail(
    @Param('token') token: string
  ): Promise<{ success: boolean; message: string }> {
    return this.authService.confirmEmail(token);
  }

  @Get('health')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Service health check (authenticated) - returns detailed metrics',
  })
  @ApiResponse({
    status: 200,
    description: 'Service health status with detailed metrics',
    type: HealthResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 503, description: 'Service unavailable' })
  async healthCheck(): Promise<HealthResponseDto> {
    const result = await this.authService.getInternalHealthMetrics();
    return {
      status: result.status,
      details: result.details,
    };
  }

  @Get('public-health')
  @ApiOperation({ summary: 'Public health check - minimal status only' })
  @ApiResponse({
    status: 200,
    description: 'Service health status (minimal)',
    type: HealthResponseDto,
  })
  @ApiResponse({ status: 503, description: 'Service unavailable' })
  async publicHealthCheck(): Promise<HealthResponseDto> {
    const result = await this.authService.getHealthStatus();
    return {
      status: result.status,
    };
  }

  @Get('fetchuser')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Fetch current user profile' })
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
    type: UserResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async fetchUser(@CurrentUser() user: UserPayload): Promise<UserResponseDto> {
    return this.authService.fetchUser(user.id);
  }

  @Post('fetchuserbyid')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Fetch user by ID' })
  @ApiResponse({
    status: 200,
    description: 'User fetched successfully',
    type: UserResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid user ID format' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async fetchUserById(
    @Body() fetchUserDto: FetchUserByIdDto
  ): Promise<UserResponseDto> {
    return this.authService.fetchUserById(fetchUserDto.userId);
  }

  @Put('update')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update user profile' })
  @ApiResponse({
    status: 200,
    description: 'Profile updated successfully',
    type: UserResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid update data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 409, description: 'Username or email already taken' })
  async updateUser(
    @CurrentUser() user: UserPayload,
    @Body() updateDto: UpdateUserDto
  ): Promise<UserResponseDto> {
    return this.authService.updateUser(user.id, updateDto);
  }

  @Patch('update')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update user profile (partial)' })
  @ApiResponse({
    status: 200,
    description: 'Profile updated successfully',
    type: UserResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid update data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 409, description: 'Username or email already taken' })
  async patchUser(
    @CurrentUser() user: UserPayload,
    @Body() updateDto: UpdateUserDto
  ): Promise<UserResponseDto> {
    return this.authService.updateUser(user.id, updateDto);
  }

  @Delete('delete')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Delete user account' })
  @ApiResponse({
    status: 200,
    description: 'Account deleted successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 500, description: 'Failed to delete account' })
  async deleteUser(
    @CurrentUser() user: UserPayload
  ): Promise<MessageResponseDto> {
    return this.authService.deleteUser(user.id);
  }

  @Post('resend-confirmation-email')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Resend confirmation email' })
  @ApiResponse({
    status: 200,
    description: 'Confirmation email sent successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 409, description: 'Email already confirmed' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async resendConfirmationEmail(
    @CurrentUser() user: UserPayload
  ): Promise<MessageResponseDto> {
    return this.authService.resendConfirmationEmail(user.id);
  }
}
