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
  Res,
  HttpException,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiExtraModels,
  getSchemaPath,
} from '@nestjs/swagger';
import { RefreshTokenDto } from '@/auth/dto/refresh-token.dto';
import { RefreshResponseDto } from '@/auth/dto/refresh-response.dto';
import type { Request } from 'express';
import type { Response } from 'express';
import { readFile } from 'node:fs/promises';
import { AuthService } from '@/auth/auth.service';
import { RegisterDto } from '@/auth/dto/register.dto';
import { LoginDto } from '@/auth/dto/login.dto';
import { ForgotPasswordDto } from '@/auth/dto/forgot-password.dto';
import { ResetPasswordDto } from '@/auth/dto/reset-password.dto';
import { UpdateUserDto } from '@/auth/dto/update-user.dto';
import { FetchUserByIdDto } from '@/auth/dto/fetch-user-by-id.dto';
import { AuthResponseDto } from '@/auth/dto/auth-response.dto';
import { RegistrationResponseDto } from '@/auth/dto/registration-response.dto';
import { GoogleOAuthExchangeDto } from '@/auth/dto/google-oauth-exchange.dto';
import {
  MessageResponseDto,
  PrivateUserResponseDto,
} from '@/auth/dto/user-response.dto';
import { UsersListResponseDto } from '@/auth/dto/users-list.dto';
import { ResendConfirmationDto } from '@/auth/dto/resend-confirmation.dto';
import { ChangeRoleDto } from '@/auth/dto/change-role.dto';
import { RoleResponseDto } from '@/auth/dto/role-response.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RefreshJwtGuard } from '@/auth/guards/refresh-jwt.guard';
import { AdminGuard } from '@/auth/guards/admin.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { Role } from '@/auth/enums/role.enum';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { TwoFASetupResponseDto } from '@/auth/dto/2fa-setup.dto';
import { TwoFAVerifyDto } from '@/auth/dto/2fa-verify.dto';
import { TwoFALoginDto } from '@/auth/dto/2fa-login.dto';
import { BanUserDto, BanResponseDto } from '@/auth/dto/ban-user.dto';
import { GoogleAuthGuard } from '@/auth/guards/google-auth.guard';
import { GoogleCallbackGuard } from '@/auth/guards/google-callback.guard';
import { type GoogleAuthUser } from '@/auth/strategies/google.strategy';

@ApiTags('Authentication')
@ApiExtraModels(AuthResponseDto)
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({ summary: 'Start Google OAuth login/signup flow' })
  @ApiResponse({
    status: 302,
    description: 'Redirects to Google OAuth consent',
  })
  googleAuth(): void {
    // Passport guard handles redirect to Google OAuth consent page.
  }

  @Get('google/callback')
  @UseGuards(GoogleCallbackGuard)
  @ApiOperation({
    summary: 'Handle Google OAuth callback and redirect to frontend',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirects to frontend callback route',
  })
  async googleCallback(
    @Req() req: Request,
    @Res() res?: Response
  ): Promise<void> {
    try {
      const googleUser = req.user as GoogleAuthUser | undefined;
      if (!googleUser) {
        throw new BadRequestException(
          'Google authentication failed: no user returned'
        );
      }

      const redirectUrl = await this.authService.handleGooglePassportCallback({
        googleUser,
        state: googleUser.state,
      });
      res?.redirect(redirectUrl);
    } catch (error) {
      const frontendBase = process.env.FRONTEND_URL ?? 'http://localhost:3000';
      const fallback = new URL('/en/login', frontendBase);

      fallback.searchParams.set('oauthError', 'google_callback_failed');

      if (error instanceof HttpException) {
        fallback.searchParams.set('statusCode', String(error.getStatus()));
      }

      res?.redirect(fallback.toString());
    }
  }

  @Post('google/exchange')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Exchange one-time Google OAuth code for login response',
  })
  @ApiResponse({
    status: 200,
    description: 'OAuth code exchanged successfully',
    schema: {
      oneOf: [
        { $ref: getSchemaPath(AuthResponseDto) },
        {
          type: 'object',
          properties: {
            tempToken: { type: 'string' },
            twoFactorRequired: { type: 'boolean' },
          },
          required: ['tempToken', 'twoFactorRequired'],
        },
      ],
    },
  })
  @ApiResponse({ status: 401, description: 'OAuth code is invalid or expired' })
  async exchangeGoogleOAuthCode(
    @Body() dto: GoogleOAuthExchangeDto
  ): Promise<
    AuthResponseDto | { tempToken: string; twoFactorRequired: boolean }
  > {
    return this.authService.exchangeGoogleOAuthCode(dto.oauthCode);
  }

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
    schema: {
      oneOf: [
        { $ref: getSchemaPath(AuthResponseDto) },
        {
          type: 'object',
          properties: {
            tempToken: { type: 'string' },
            twoFactorRequired: { type: 'boolean' },
          },
          required: ['tempToken', 'twoFactorRequired'],
        },
      ],
    },
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 403, description: 'Account locked or deactivated' })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request
  ): Promise<
    AuthResponseDto | { tempToken: string; twoFactorRequired: boolean }
  > {
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    return this.authService.login(loginDto, ip);
  }

  @Post('2fa/setup')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Setup 2FA (generate secret, QR)' })
  @ApiResponse({
    status: 200,
    description: '2FA setup info',
    type: TwoFASetupResponseDto,
  })
  async setup2FA(
    @CurrentUser() user: UserPayload
  ): Promise<TwoFASetupResponseDto> {
    const result = await this.authService.setupTwoFactor(user.id);
    return { qrCode: result.qrCode, secret: result.secret };
  }

  @Post('2fa/verify')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify and enable 2FA' })
  @ApiResponse({ status: 200, description: '2FA enabled' })
  async verify2FA(
    @CurrentUser() user: UserPayload,
    @Body() dto: TwoFAVerifyDto,
    @Req() req: Request
  ): Promise<{ enabled: boolean }> {
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    this.authService.check2FAVerificationLimit(user.email, ip);
    const enabled = await this.authService.verifyTwoFactor(user.id, dto.code);
    this.authService.record2FAAttempt(user.email, ip, enabled);
    return { enabled };
  }

  @Post('2fa/disable')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Disable 2FA' })
  @ApiResponse({ status: 200, description: '2FA disabled' })
  @ApiResponse({ status: 400, description: '2FA is not enabled' })
  @ApiResponse({ status: 401, description: 'Invalid 2FA code' })
  async disable2FA(
    @CurrentUser() user: UserPayload,
    @Body() dto: TwoFAVerifyDto,
    @Req() req: Request
  ): Promise<{ disabled: boolean }> {
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    await this.authService.disableTwoFactor(user.id, dto.code, {
      email: user.email,
      ip,
    });
    return { disabled: true };
  }

  @Post('2fa/login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: '2FA login step (validate temp token + TOTP)' })
  @ApiResponse({
    status: 200,
    description: 'Full JWT issued',
    type: AuthResponseDto,
  })
  async twoFactorLogin(
    @Body() dto: TwoFALoginDto,
    @Req() req: Request
  ): Promise<AuthResponseDto> {
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    return this.authService.twoFactorLogin(dto.tempToken, dto.code, ip);
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
    type: RefreshResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid token format' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async refreshTokenHandler(
    @CurrentUser() user: UserPayload,
    @Req() req: Request
  ): Promise<RefreshResponseDto> {
    const authHeader = req.headers.authorization;
    const oldRefreshToken = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7)
      : '';

    if (!oldRefreshToken) {
      throw new BadRequestException('Invalid token format');
    }

    const tokens = this.authService.generateTokens(user);

    await this.authService.updateRefreshToken(
      user.id,
      oldRefreshToken,
      tokens.refreshToken
    );

    const accessTokenExpiresAt = new Date(
      Date.now() + AuthService.TOKEN_EXPIRY_DURATIONS.accessMs
    ).toISOString();
    const refreshTokenExpiresAt = new Date(
      Date.now() + AuthService.TOKEN_EXPIRY_DURATIONS.refreshMs
    ).toISOString();

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
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
      const templatePath = `${process.cwd()}/src/auth/templates/email_confirmed.html`;
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

  @Get('fetchuser')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Fetch current user profile' })
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
    type: PrivateUserResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async fetchUser(
    @CurrentUser() user: UserPayload
  ): Promise<PrivateUserResponseDto> {
    return this.authService.fetchUser(user.id);
  }

  @Post('fetchuserbyid')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Fetch user by ID' })
  @ApiResponse({
    status: 200,
    description: 'User fetched successfully',
    type: PrivateUserResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid user ID format' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async fetchUserById(
    @CurrentUser() requester: UserPayload,
    @Body() fetchUserDto: FetchUserByIdDto
  ): Promise<PrivateUserResponseDto> {
    return this.authService.fetchUserById(fetchUserDto.userId, {
      id: requester.id,
      role: requester.role,
    });
  }

  @Put('update')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update user profile' })
  @ApiResponse({
    status: 200,
    description: 'Profile updated successfully',
    type: PrivateUserResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid update data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 409, description: 'Username or email already taken' })
  async updateUser(
    @CurrentUser() user: UserPayload,
    @Body() updateDto: UpdateUserDto
  ): Promise<PrivateUserResponseDto> {
    return this.authService.updateUser(user.id, updateDto);
  }

  @Patch('update')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update user profile (partial)' })
  @ApiResponse({
    status: 200,
    description: 'Profile updated successfully',
    type: PrivateUserResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid update data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 409, description: 'Username or email already taken' })
  async patchUser(
    @CurrentUser() user: UserPayload,
    @Body() updateDto: UpdateUserDto
  ): Promise<PrivateUserResponseDto> {
    return this.authService.updateUser(user.id, updateDto);
  }

  @Patch('deactivate')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Deactivate your own user account (Soft Delete)' })
  @ApiResponse({
    status: 200,
    description: 'Account deactivated successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Cannot deactivate admin accounts' })
  @ApiResponse({ status: 500, description: 'Failed to deactivate account' })
  async deactivateUser(
    @CurrentUser() user: UserPayload
  ): Promise<MessageResponseDto> {
    return this.authService.deleteUser(user.id);
  }

  @Patch('users/:id/deactivate')
  @UseGuards(JwtAuthGuard, AdminGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: deactivate a user by id (Soft Delete)' })
  @ApiResponse({
    status: 200,
    description: 'User deactivated successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Insufficient privileges' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({
    status: 400,
    description: 'Administrators cannot deactivate themselves',
  })
  async deactivateUserByAdmin(
    @CurrentUser() user: UserPayload,
    @Param('id') id: string
  ): Promise<MessageResponseDto> {
    return this.authService.deleteUserByAdmin(user.id, id);
  }

  @Patch('users/:id/reactivate')
  @UseGuards(JwtAuthGuard, AdminGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: reactivate a deactivated user' })
  @ApiResponse({
    status: 200,
    description: 'User reactivated successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Insufficient privileges' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async reactivateUserByAdmin(
    @CurrentUser() user: UserPayload,
    @Param('id') id: string
  ): Promise<MessageResponseDto> {
    return this.authService.reactivateUserByAdmin(user.id, id);
  }

  @Get('users')
  @UseGuards(JwtAuthGuard, AdminGuard)
  @ApiOperation({ summary: 'Admin: fetch all users' })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, type: UsersListResponseDto })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async getAllUsers(): Promise<UsersListResponseDto> {
    return this.authService.fetchAllUsers();
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

  @Patch('change-role')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change user role (Platform Owner/Admin only)' })
  @ApiResponse({
    status: 200,
    description: 'User role changed successfully',
    type: RoleResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions',
  })
  @ApiResponse({ status: 404, description: 'User not found' })
  async changeUserRole(
    @Body() changeRoleDto: ChangeRoleDto,
    @CurrentUser() currentUser: UserPayload
  ): Promise<RoleResponseDto> {
    return this.authService.changeUserRole(
      changeRoleDto.userId,
      changeRoleDto.newRole,
      currentUser
    );
  }

  @Patch('users/:id/ban')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Ban a user (Platform Owner/Admin only)' })
  @ApiResponse({
    status: 200,
    description: 'User banned successfully',
    type: BanResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions',
  })
  @ApiResponse({ status: 404, description: 'User not found' })
  async banUser(
    @CurrentUser() currentUser: UserPayload,
    @Param('id') id: string,
    @Body() banDto: BanUserDto
  ): Promise<BanResponseDto> {
    return this.authService.banUser(currentUser.id, id, banDto.reason);
  }

  @Patch('users/:id/unban')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Unban a user (Platform Owner/Admin only)' })
  @ApiResponse({
    status: 200,
    description: 'User unbanned successfully',
    type: BanResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions',
  })
  @ApiResponse({ status: 404, description: 'User not found' })
  async unbanUser(
    @CurrentUser() currentUser: UserPayload,
    @Param('id') id: string
  ): Promise<BanResponseDto> {
    return this.authService.unbanUser(currentUser.id, id);
  }
}
