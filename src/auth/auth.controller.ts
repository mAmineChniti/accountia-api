import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Get,
  Patch,
  Delete,
  Req,
  Param,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtService } from '@nestjs/jwt';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import type { Request } from 'express';
import type { Response } from 'express';
import { readFile } from 'node:fs/promises';
import { AuthService } from '@/auth/auth.service';
import { UsersService } from '@/users/users.service';
import { RegisterDto } from '@/auth/dto/register.dto';
import { LoginDto } from '@/auth/dto/login.dto';
import { ForgotPasswordDto } from '@/auth/dto/forgot-password.dto';
import { ResetPasswordDto } from '@/auth/dto/reset-password.dto';
import { UpdateUserDto } from '@/auth/dto/update-user.dto';
import { FetchUserByIdDto } from '@/auth/dto/fetch-user-by-id.dto';
import { ChangePasswordDto } from '@/users/dto/change-password.dto';
import { MessageResponseDto } from '@/users/dto/message-response.dto';
import { AuthResponseDto } from '@/auth/dto/auth-response.dto';
import { RegistrationResponseDto } from '@/auth/dto/registration-response.dto';
import {
  UserResponseDto,
  HealthResponseDto,
} from '@/auth/dto/user-response.dto';
import { ResendConfirmationDto } from '@/auth/dto/resend-confirmation.dto';
import { TwoFactorSetupResponseDto } from '@/auth/dto/two-factor.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RefreshJwtGuard } from '@/auth/guards/refresh-jwt.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 201,
    description: 'User successfully registered',
    type: RegistrationResponseDto,
  })
  @ApiResponse({ status: 409, description: 'User already exists' })
  async register(
    @Body() registerDto: RegisterDto
  ): Promise<RegistrationResponseDto> {
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
    @Req() req: Request,
    @Res() res: Response
  ): Promise<void> {
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    const result = await this.authService.login(loginDto, ip);
    
    // Set tokens in cookies
    res.cookie('accessToken', result.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });
    
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    
    // Also return in body for backwards compatibility
    res.json(result);
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
    @CurrentUser() user: UserPayload,
    @Req() req: Request
  ): Promise<AuthResponseDto> {
    const authHeader = req.headers.authorization;
    const oldRefreshToken = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7)
      : '';

    const tokens = this.authService.generateTokens(user);

    await this.authService.updateRefreshToken(
      user.id,
      oldRefreshToken,
      tokens.refreshToken
    );

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      accessTokenExpiresAt: new Date(
        Date.now() + 24 * 60 * 60 * 1000
      ).toISOString(),
      refreshTokenExpiresAt: new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
      ).toISOString(),
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
    @Param('token') token: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<{ success: boolean; message?: string } | void> {
    const result = await this.authService.confirmEmail(token);

    try {
      const templatePath = './templates/email_confirmed.html';
      const template = await readFile(templatePath, 'utf8');

      const year = new Date().getFullYear();
      let html = template.replaceAll('{{.Year}}', year.toString());

      if (result.success) {
        // Remove entire else block and remaining markers
        html = html.replaceAll(/{{else}}[\S\s]*?{{end}}/g, '');
        html = html.replaceAll('{{if .Success}}', '').replaceAll('{{end}}', '');
        html = html.replaceAll('{{.Message}}', '');
      } else {
        // Remove if block and remaining markers
        html = html.replaceAll(/{{if .Success}}[\S\s]*?{{else}}/g, '');
        html = html.replaceAll('{{end}}', '');
        html = html.replaceAll('{{.Message}}', result.message);
      }

      res.setHeader('Content-Type', 'text/html');
      res.send(html);
      return;
    } catch {
      return result;
    }
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

  @Patch('change-password')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Change user password',
    description: 'Change the password of the authenticated user',
  })
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input or new password same as current password',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized or current password is incorrect',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  async changePassword(
    @CurrentUser() user: UserPayload,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<MessageResponseDto> {
    return this.usersService.changePassword(user.id, changePasswordDto);
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
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Resend confirmation email' })
  @ApiResponse({
    status: 200,
    description: 'Confirmation email sent successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 409, description: 'Email already confirmed' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async resendConfirmationEmail(
    @Body() resendConfirmationDto: ResendConfirmationDto
  ): Promise<MessageResponseDto> {
    return this.authService.resendConfirmationEmail(
      resendConfirmationDto.email
    );
  }

  @Post('2fa/setup')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Setup 2FA - Generate secret and QR code' })
  @ApiResponse({
    status: 200,
    description: '2FA setup initialized',
    type: TwoFactorSetupResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 409, description: '2FA already enabled' })
  async setup2FA(
    @CurrentUser() user: UserPayload
  ): Promise<TwoFactorSetupResponseDto> {
    return this.authService.setupTwoFactor(user.id);
  }

  @Post('2fa/enable')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify and enable 2FA' })
  @ApiResponse({
    status: 200,
    description: '2FA enabled successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid OTP code' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async enable2FA(
    @CurrentUser() user: UserPayload,
    @Body() body: { code: string; secret: string; backupCodes: string[] }
  ): Promise<MessageResponseDto> {
    return this.authService.enableTwoFactor(
      user.id,
      body.code,
      body.secret,
      body.backupCodes
    );
  }

  @Delete('2fa/disable')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Disable 2FA' })
  @ApiResponse({
    status: 200,
    description: '2FA disabled successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 400, description: '2FA not enabled' })
  @ApiResponse({ status: 401, description: 'Unauthorized or invalid password' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async disable2FA(
    @CurrentUser() user: UserPayload,
    @Body() body: { password: string }
  ): Promise<MessageResponseDto> {
    return this.authService.disableTwoFactor(user.id, body.password);
  }

  @Post('2fa/verify')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify 2FA code during login' })
  @ApiResponse({
    status: 200,
    description: '2FA code verified',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid 2FA code' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async verify2FA(
    @Body() body: { userId: string; code: string }
  ): Promise<MessageResponseDto> {
    const isValid = await this.authService.verifyTwoFactorDuringLogin(
      body.userId,
      body.code
    );
    if (isValid) {
      return { message: '2FA code verified successfully' };
    }
    throw new UnauthorizedException('Invalid 2FA code');
  }

  @Get('check')
  @ApiOperation({ summary: 'Check if user is authenticated (optional)', description: 'Public endpoint to check if user is logged in. Returns user data if authenticated, null if not.' })
  @ApiResponse({
    status: 200,
    description: 'Authentication check completed',
    schema: {
      properties: {
        authenticated: { type: 'boolean' },
        user: {
          type: 'object',
          nullable: true,
          properties: {
            id: { type: 'string' },
            email: { type: 'string' },
            username: { type: 'string' },
            firstName: { type: 'string' },
            lastName: { type: 'string' },
          },
        },
      },
    },
  })
  async checkAuth(@Req() request: Request) {
    try {
      // Try to extract token from Authorization header or cookies
      let token: string | undefined;

      // Try Authorization header first
      const authHeader = request.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }

      // Try cookies if no header token
      const cookies = request.cookies as Record<string, string> | undefined;
      if (!token && cookies?.accessToken) {
        token = cookies.accessToken;
      }

      // If no token found, return unauthenticated response
      if (!token) {
        return {
          authenticated: false,
          user: undefined,
        };
      }

      // Try to validate the token
      const payload = this.jwtService.verify(token) as { sub: string; email: string; username: string };
      
      // Token is valid, try to fetch the user
      try {
        const user = await this.authService.fetchUser(payload.sub);
        return {
          authenticated: true,
          user: {
            id: payload.sub,
            email: payload.email,
            username: payload.username,
            firstName: user.user.firstName,
            lastName: user.user.lastName,
          },
        };
      } catch {
        // User not found or other error
        return {
          authenticated: false,
          user: undefined,
        };
      }
    } catch {
      // Token validation failed or other error
      return {
        authenticated: false,
        user: undefined,
      };
    }
  }

  @Get('2fa/status')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get 2FA status' })
  @ApiResponse({
    status: 200,
    description: '2FA status retrieved',
    schema: {
      properties: {
        twoFactorEnabled: { type: 'boolean' },
        backupCodesRemaining: { type: 'number' },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async get2FAStatus(@CurrentUser() user: UserPayload) {
    return this.authService.getTwoFactorStatus(user.id);
  }
}
