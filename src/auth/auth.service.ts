import {
  Injectable,
  Logger,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
  HttpException,
  HttpStatus,
  InternalServerErrorException,
  Inject,
  forwardRef,
} from '@nestjs/common';
import Stripe from 'stripe';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import { Connection, Model, Types, Document } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { JsonWebTokenError, type JwtPayload } from 'jsonwebtoken';
import { hash, compare } from 'bcrypt';
import multiavatar from '@multiavatar/multiavatar';
import { randomBytes, randomUUID } from 'node:crypto';
import { User } from '@/users/schemas/user.schema';
import { RegisterDto } from '@/auth/dto/register.dto';
import { AuditEmitter } from '@/audit/audit.emitter';
import { AuditAction } from '@/audit/schemas/audit-log.schema';
import { LoginDto } from '@/auth/dto/login.dto';
import { RefreshTokenDto } from '@/auth/dto/refresh.dto';
import { ForgotPasswordDto } from '@/auth/dto/forgot-password.dto';
import { ResetPasswordDto } from '@/auth/dto/reset-password.dto';
import { UpdateUserDto } from '@/auth/dto/update-user.dto';
import { AuthResponseDto } from '@/auth/dto/auth-response.dto';
import { RegistrationResponseDto } from '@/auth/dto/registration-response.dto';
import {
  MessageResponseDto,
  PrivateUserResponseDto,
  PrivateUserDto,
} from '@/auth/dto/user-response.dto';
import { UsersListResponseDto } from '@/auth/dto/users-list.dto';
import { EmailService } from '@/email/email.service';
import { RateLimitingService } from '@/auth/rate-limiting.service';
import { Role } from '@/auth/enums/role.enum';
import { RoleResponseDto } from '@/auth/dto/role.dto';
import { BanResponseDto } from '@/auth/dto/ban-user.dto';
import { type UserPayload } from '@/auth/types/auth.types';
import { BusinessInvite } from '@/business/schemas/business-invite.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { BusinessService } from '@/business/business.service';
import { Business } from '@/business/schemas/business.schema';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';

import {
  UserStripeOnboardingLinkDto,
  UserStripeConnectStatusDto,
} from '@/auth/dto/stripe-connect.dto';

import { generateSecret, verify, generateURI } from 'otplib';

// eslint-disable-next-line @typescript-eslint/consistent-type-imports
let qrcodeModule: typeof import('qrcode') | undefined;

const getQrcode = async () => {
  qrcodeModule ??= await import('qrcode');
  return qrcodeModule;
};

interface TokenPayload {
  sub?: string;
  id: string;
  email: string;
  role: string;
}

type TwoFactorChallengeResponse = {
  tempToken: string;
  twoFactorRequired: boolean;
};

type GoogleStateTokenPayload = {
  type: 'google-oauth-state';
  mode: 'login' | 'register';
  lang: string;
  redirectUri: string;
  nonce: string;
  iat?: number;
  exp?: number;
};

type GoogleTokenInfo = {
  email: string;
  given_name?: string;
  family_name?: string;
  name?: string;
  picture?: string;
};

type GoogleOAuthInitParams = {
  mode: 'login' | 'register';
  lang: string;
  redirectUri?: string;
  ip: string;
};

type GoogleAuthCodeRecord = {
  code: string;
  payload: AuthResponseDto | TwoFactorChallengeResponse;
  expiresAt: Date;
};

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  static readonly TOKEN_EXPIRY_DURATIONS = {
    accessMs: 15 * 60 * 1000, // 15 minutes
    refreshMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  };

  private readonly stripe: InstanceType<typeof Stripe>;

  private oauthIndexesInitialized = false;

  private static readonly GOOGLE_STATE_TTL_MS = 10 * 60 * 1000;
  private static readonly GOOGLE_AUTH_CODE_TTL_MS = 2 * 60 * 1000;
  private static readonly GOOGLE_STATE_NONCE_COLLECTION =
    'auth_google_state_nonces';
  private static readonly GOOGLE_AUTH_CODE_COLLECTION =
    'auth_google_oauth_codes';
  private static readonly LANG_PATTERN = /^[a-z]{2}(?:-[A-Z]{2})?$/;

  constructor(
    @InjectConnection() private readonly connection: Connection,
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(BusinessInvite.name)
    private businessInviteModel: Model<BusinessInvite>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUser>,
    @InjectModel(Business.name) private businessModel: Model<Business>,
    private jwtService: JwtService,
    private emailService: EmailService,
    private rateLimitingService: RateLimitingService,
    private auditEmitter: AuditEmitter,
    private tenantConnectionService: TenantConnectionService,
    @Inject(forwardRef(() => BusinessService))
    private businessService: BusinessService
  ) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-explicit-any
    this.stripe = new (Stripe as any)(process.env.STRIPE_SECRET_KEY ?? '', {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-explicit-any
      apiVersion: '2022-11-15' as any,
    });
  }

  async buildGoogleOAuthState(params: GoogleOAuthInitParams): Promise<string> {
    await this.cleanupExpiredOAuthEntries();

    const rateLimit = await this.rateLimitingService.checkOAuthStateRequests(
      params.ip
    );
    if (!rateLimit.allowed) {
      throw new HttpException(
        'Too many OAuth requests. Please try again later.',
        HttpStatus.TOO_MANY_REQUESTS
      );
    }
    await this.rateLimitingService.recordOAuthStateRequest(params.ip);

    const lang = this.normalizeLang(params.lang);

    const sanitizedRedirectUri = this.resolveFrontendRedirectUri(
      params.redirectUri,
      lang
    );

    const nonce = randomBytes(16).toString('hex');
    const nonceExpiresAt = Date.now() + AuthService.GOOGLE_STATE_TTL_MS;
    await this.setGoogleStateNonce(nonce, nonceExpiresAt);

    const payload: GoogleStateTokenPayload = {
      type: 'google-oauth-state',
      mode: params.mode,
      lang,
      redirectUri: sanitizedRedirectUri,
      nonce,
    };

    return this.jwtService.sign(payload, {
      expiresIn: '10m',
      jwtid: randomUUID(),
    });
  }

  async handleGooglePassportCallback(params: {
    googleUser: GoogleTokenInfo;
    state?: string;
  }): Promise<string> {
    try {
      if (!params.state) {
        throw new BadRequestException('Missing Google OAuth state');
      }
      const stateData = await this.parseGoogleState(params.state);

      if (!params.googleUser.email) {
        throw new UnauthorizedException('Google identity token is not valid');
      }

      const user = await this.findOrCreateGoogleUser(params.googleUser);

      if (user.isBanned) {
        throw new ForbiddenException(
          'Your account has been banned. Please contact support.'
        );
      }

      if (user.twoFactorEnabled) {
        const tempToken = this.generateTempToken(user);
        const oauthCode = await this.createGoogleOAuthCode({
          tempToken,
          twoFactorRequired: true,
        });

        const redirectUrl = new URL(stateData.redirectUri);
        redirectUrl.searchParams.set('oauthCode', oauthCode);
        return redirectUrl.toString();
      }

      const tokens = this.generateTokens(user);

      await this.userModel.updateOne(
        { _id: (user as unknown as { _id: Types.ObjectId })._id },
        {
          $push: {
            refreshTokens: {
              $each: [
                {
                  token: tokens.refreshToken,
                  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                },
              ],
              $slice: -10,
            },
          },
        }
      );

      const authResponse = this.buildAuthResponse(tokens, user);
      const oauthCode = await this.createGoogleOAuthCode(authResponse);
      const redirectUrl = new URL(stateData.redirectUri);
      redirectUrl.searchParams.set('oauthCode', oauthCode);

      return redirectUrl.toString();
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      throw new InternalServerErrorException(
        'Google OAuth callback failed unexpectedly'
      );
    }
  }

  async check2FAVerificationLimit(email: string, ip: string): Promise<void> {
    const rateLimitResult = await this.rateLimitingService.checkLoginAttempts(
      email,
      ip
    );
    if (!rateLimitResult.allowed) {
      throw new HttpException(
        'Too many 2FA attempts. Please try again later.',
        HttpStatus.TOO_MANY_REQUESTS
      );
    }
  }

  async record2FAAttempt(
    email: string,
    ip: string,
    codeValid: boolean
  ): Promise<void> {
    await (codeValid
      ? this.rateLimitingService.clearLoginAttempts(email, ip)
      : this.rateLimitingService.recordFailedLogin(email, ip));
  }

  async setupTwoFactor(
    userId: string
  ): Promise<{ qrCode: string; secret: string }> {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('User not found');
    if (user.twoFactorEnabled)
      throw new BadRequestException('2FA already enabled');

    const { toDataURL } = await getQrcode();

    const appName = process.env.APP_NAME ?? 'Accountia';
    const secret = generateSecret();

    user.twoFactorTempSecret = secret;
    await user.save();

    const otpauthUrl = generateURI({
      issuer: appName,
      label: user.email,
      secret,
    });
    const qrCode = await toDataURL(otpauthUrl);
    return { qrCode: qrCode ?? '', secret };
  }

  async verifyTwoFactor(userId: string, code: string): Promise<boolean> {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('User not found');
    if (!user.twoFactorTempSecret)
      throw new BadRequestException('No 2FA setup in progress');

    const result = await verify({
      secret: user.twoFactorTempSecret,
      token: code,
    });
    const isValid = result.valid === true;

    if (!isValid) return false;

    user.twoFactorSecret = user.twoFactorTempSecret;
    user.twoFactorEnabled = true;
    user.twoFactorTempSecret = undefined;
    await user.save();
    return true;
  }

  async disableTwoFactor(
    userId: string,
    code: string,
    context: { email: string; ip: string }
  ): Promise<void> {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('User not found');
    if (!user.twoFactorEnabled)
      throw new BadRequestException('2FA is not enabled');

    await this.check2FAVerificationLimit(context.email, context.ip);

    const result = await verify({
      secret: user.twoFactorSecret!,
      token: code,
    });
    if (result.valid !== true) {
      await this.record2FAAttempt(context.email, context.ip, false);
      throw new UnauthorizedException('Invalid 2FA code');
    }

    await this.record2FAAttempt(context.email, context.ip, true);

    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.twoFactorTempSecret = undefined;
    await user.save();
  }

  generateTempToken(user: User): string {
    return this.jwtService.sign(
      { sub: user._id.toString(), type: '2fa-temp' },
      { expiresIn: '5m', jwtid: randomUUID() }
    );
  }

  async twoFactorLogin(
    tempToken: string,
    code: string,
    ip: string
  ): Promise<AuthResponseDto> {
    let payload: JwtPayload;
    try {
      payload = this.jwtService.verify(tempToken);
    } catch {
      throw new UnauthorizedException('Invalid or expired temp token');
    }

    if (payload.type !== '2fa-temp') {
      throw new UnauthorizedException('Invalid token type');
    }

    const user = await this.userModel.findById(payload.sub);
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret)
      throw new UnauthorizedException('2FA not enabled');

    await this.check2FAVerificationLimit(user.email, ip);

    const result = await verify({ secret: user.twoFactorSecret, token: code });
    const isValid = result.valid === true;

    if (!isValid) {
      await this.record2FAAttempt(user.email, ip, false);
      throw new UnauthorizedException('Invalid 2FA code');
    }

    await this.record2FAAttempt(user.email, ip, true);
    const tokens = this.generateTokens(user);
    await this.userModel.updateOne(
      { _id: user._id },
      {
        $push: {
          refreshTokens: {
            $each: [
              {
                token: tokens.refreshToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
              },
            ],
            $slice: -10,
          },
        },
      }
    );
    return this.buildAuthResponse(tokens, user);
  }

  private buildAuthResponse(
    tokens: { accessToken: string; refreshToken: string },
    user: User
  ): AuthResponseDto {
    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      accessTokenExpiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      refreshTokenExpiresAt: new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
      ).toISOString(),
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        birthdate: user.birthdate,
        profilePicture: user.profilePicture,
        role: user.role,
      },
    };
  }

  async register(registerDto: RegisterDto): Promise<RegistrationResponseDto> {
    const {
      username,
      email,
      password,
      firstName,
      lastName,
      birthdate,
      phoneNumber,
      acceptTerms,
      profilePicture,
    } = registerDto;
    const normalizedEmail = email.toLowerCase().trim();

    if (!acceptTerms) {
      throw new BadRequestException('You must accept the terms and conditions');
    }

    const existingUsername = await this.userModel.findOne({ username });
    if (existingUsername) {
      throw new ConflictException('This username is already taken');
    }

    const existingEmail = await this.userModel.findOne({
      email: normalizedEmail,
    });
    if (existingEmail) {
      const error = existingEmail.emailConfirmed
        ? new ConflictException('This email is already registered')
        : new ConflictException(
            'Account exists but email is not confirmed. Please check your email or request a new confirmation.'
          );
      throw error;
    }

    const pendingInvites = await this.businessInviteModel.find({
      invitedEmail: normalizedEmail,
      status: 'pending',
    });

    const passwordHash = await hash(password, 10);
    const emailTokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const emailTokenGeneratedAt = new Date();
    const isInvited = pendingInvites.length > 0;
    let invitesProcessed = false;

    try {
      const birthdateDate = new Date(birthdate);
      if (Number.isNaN(birthdateDate.getTime())) {
        throw new BadRequestException('Failed to parse birthdate');
      }

      let finalProfilePicture = profilePicture;
      if (!finalProfilePicture) {
        const svg = multiavatar(username);
        finalProfilePicture =
          'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64');
      }

      const user = new this.userModel({
        username,
        email: normalizedEmail,
        passwordHash,
        firstName,
        lastName,
        birthdate: birthdateDate,
        phoneNumber,
        acceptTerms,
        profilePicture: finalProfilePicture,
        emailConfirmed: isInvited,
        ...(isInvited
          ? {}
          : {
              emailToken: this.generateEmailToken(),
              emailTokenExpiresAt,
              emailTokenGeneratedAt,
            }),
      });

      await user.save();

      if (isInvited) {
        try {
          await this.businessService.processInvitesForNewUser(
            user._id.toString(),
            normalizedEmail
          );
          invitesProcessed = true;
        } catch (error) {
          const errorMessage =
            error instanceof Error ? error.message : String(error);
          this.logger.error(
            'Failed to process business invites during registration',
            error instanceof Error ? error.stack : errorMessage
          );
          await this.auditEmitter.emitAction({
            action: AuditAction.OTHER,
            userId: user._id.toString(),
            userEmail: user.email,
            userRole: user.role || 'CLIENT',
            details: {
              reason: 'invite_processing_failed_during_registration',
              invitedToBusinesses: pendingInvites.length,
              error: errorMessage,
            },
          });
          await this.userModel.findByIdAndDelete(user._id);
          throw new InternalServerErrorException(
            'Failed to process business invitation. Please try again later.'
          );
        }
      } else {
        void this.emailService
          .sendConfirmationEmail(normalizedEmail, user.emailToken!)
          .catch((error) => {
            this.logger.error('Failed to send confirmation email', error);
          });
      }

      await this.auditEmitter.emitAction({
        action: AuditAction.REGISTER,
        userId: user._id.toString(),
        userEmail: user.email,
        userRole: user.role || 'CLIENT',
        details: {
          method: 'standard',
          autoConfirmed: isInvited,
          invitedToBusinesses: pendingInvites.length,
        },
      });

      let registrationMessage =
        'Registration successful! Please check your email to confirm your account.';
      if (isInvited) {
        registrationMessage = invitesProcessed
          ? 'Registration successful! You have been automatically added to your invited businesses.'
          : 'Registration successful! Your business invites are pending and will be processed shortly.';
      }

      return {
        message: registrationMessage,
        email: user.email,
      };
    } catch (error: unknown) {
      if (
        error instanceof Error &&
        error.message.includes('failed to hash password')
      ) {
        throw new BadRequestException('Unable to process password');
      }
      throw error;
    }
  }

  async login(
    loginDto: LoginDto,
    ip: string
  ): Promise<AuthResponseDto | TwoFactorChallengeResponse> {
    const { email, password } = loginDto;
    const normalizedEmail = email.toLowerCase().trim();
    const rateLimitResult = await this.rateLimitingService.checkLoginAttempts(
      normalizedEmail,
      ip
    );
    if (!rateLimitResult.allowed) {
      throw new HttpException(
        'Too many failed login attempts. Please try again later.',
        HttpStatus.TOO_MANY_REQUESTS
      );
    }
    const user = await this.userModel.findOne({ email: normalizedEmail });
    if (!user) {
      await this.rateLimitingService.recordFailedLogin(normalizedEmail, ip);
      await this.auditEmitter.emitAction({
        action: AuditAction.FAILED_LOGIN,
        userId: undefined,
        userEmail: normalizedEmail,
        userRole: 'unknown',
        ipAddress: ip,
        details: { reason: 'user_not_found' },
      });
      throw new UnauthorizedException('Invalid email or password');
    }
    if (user.lockUntil && user.lockUntil > new Date()) {
      throw new ForbiddenException(
        'Account is temporarily locked due to too many failed attempts'
      );
    }
    if (!user.emailConfirmed) {
      throw new ForbiddenException(
        'Email not confirmed. Please confirm your email before logging in.'
      );
    }
    if (user.isBanned) {
      throw new ForbiddenException(
        'Your account has been banned. Please contact support.'
      );
    }
    const isPasswordValid = await compare(password, user.passwordHash);
    if (!isPasswordValid) {
      await this.handleFailedLogin(user);
      await this.rateLimitingService.recordFailedLogin(normalizedEmail, ip);
      await this.auditEmitter.emitAction({
        action: AuditAction.FAILED_LOGIN,
        userId: user._id.toString(),
        userEmail: normalizedEmail,
        userRole: user.role || 'Unknown',
        ipAddress: ip,
        details: { reason: 'invalid_password' },
      });
      throw new UnauthorizedException('Invalid email or password');
    }
    if (user.twoFactorEnabled) {
      const tempToken = this.generateTempToken(user);
      return { tempToken, twoFactorRequired: true };
    }
    await this.resetFailedAttempts(user);
    await this.rateLimitingService.clearLoginAttempts(normalizedEmail, ip);
    const tokens = this.generateTokens(user);
    await this.userModel.updateOne(
      { _id: user._id },
      {
        $push: {
          refreshTokens: {
            $each: [
              {
                token: tokens.refreshToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
              },
            ],
            $slice: -10,
          },
        },
      }
    );

    await this.auditEmitter.emitAction({
      action: AuditAction.LOGIN,
      userId: user._id.toString(),
      userEmail: user.email,
      userRole: user.role || 'Unknown',
      ipAddress: ip,
      details: { method: 'standard' },
    });

    return this.buildAuthResponse(tokens, user);
  }

  async logout(
    userId: string,
    refreshToken: string,
    ipAddress?: string
  ): Promise<void> {
    const user = await this.userModel.findById(userId);

    await this.userModel.updateOne(
      { _id: userId },
      { $pull: { refreshTokens: { token: refreshToken } } }
    );

    if (user) {
      await this.auditEmitter.emitAction({
        action: AuditAction.LOGOUT,
        userId: user._id.toString(),
        userEmail: user.email,
        userRole: user.role || 'Unknown',
        ipAddress,
        details: { reason: 'user_initiated' },
      });
    }
  }

  async refreshTokens(
    refreshTokenDto: RefreshTokenDto
  ): Promise<AuthResponseDto> {
    const { refreshToken } = refreshTokenDto;

    try {
      const payload = this.jwtService.verify(refreshToken) as unknown as {
        type: string;
        sub: string;
      };

      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      const user = await this.userModel.findById(payload.sub);
      if (!user) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const tokenExists = user.refreshTokens.some(
        (rt) => rt.token === refreshToken && rt.expiresAt > new Date()
      );

      if (!tokenExists) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      const tokens = this.generateTokens(user);

      await this.userModel.updateOne(
        { _id: user._id, 'refreshTokens.token': refreshToken },
        {
          $set: {
            'refreshTokens.$.token': tokens.refreshToken,
            'refreshTokens.$.expiresAt': new Date(
              Date.now() + 7 * 24 * 60 * 60 * 1000
            ),
          },
        }
      );

      return this.buildAuthResponse(tokens, user);
    } catch (error: unknown) {
      if (error instanceof UnauthorizedException) {
        throw error;
      } else if (
        error instanceof Error &&
        error.message.includes('jwt expired')
      ) {
        throw new UnauthorizedException('Refresh token has expired');
      }
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const { email } = forgotPasswordDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      return;
    }

    const resetToken = this.generateEmailToken();

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();

    await this.emailService.sendPasswordResetEmail(email, resetToken);
    await this.auditEmitter.emitAction({
      action: AuditAction.PASSWORD_RESET_REQUEST,
      userId: user._id.toString(),
      userEmail: user.email,
      userRole: user.role || 'Unknown',
      details: { method: 'forgot_password' },
    });
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const { token, newPassword } = resetPasswordDto;

    const user = await this.userModel.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: new Date() },
    });

    if (!user) {
      throw new BadRequestException('Invalid or expired token');
    }

    user.passwordHash = await hash(newPassword, 10);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.failedLoginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();
    await this.auditEmitter.emitAction({
      action: AuditAction.PASSWORD_RESET,
      userId: user._id.toString(),
      userEmail: user.email,
      userRole: user.role || 'Unknown',
      details: { method: 'reset_token' },
    });
  }

  async confirmEmail(
    token: string
  ): Promise<{ success: boolean; message: string; user?: User }> {
    try {
      const now = new Date();
      const result = await this.userModel.findOneAndUpdate(
        {
          emailToken: token,
          emailConfirmed: false,
          $or: [
            { emailTokenExpiresAt: { $gt: now } },
            { emailTokenExpiresAt: { $exists: false } },
          ],
        },
        {
          $set: {
            emailConfirmed: true,
            emailConfirmationAttempts: 0,
          },
          $unset: {
            emailToken: '',
            emailTokenExpiresAt: '',
            emailTokenGeneratedAt: '',
          },
        },
        { returnDocument: 'after' }
      );

      if (!result) {
        const user = await this.userModel.findOne({ emailToken: token });
        if (!user) {
          return { success: false, message: 'Invalid confirmation token' };
        }
        if (user.emailConfirmed) {
          return { success: false, message: 'Email is already confirmed' };
        }
        if (!user.emailTokenExpiresAt || user.emailTokenExpiresAt < now) {
          return { success: false, message: 'Confirmation token has expired' };
        }
        return { success: false, message: 'Invalid confirmation token' };
      }

      await this.auditEmitter.emitAction({
        action: AuditAction.EMAIL_CONFIRMED,
        userId: result._id.toString(),
        userEmail: result.email,
        userRole: result.role || 'Unknown',
        details: { method: 'email_link' },
      });

      return {
        success: true,
        message: 'Email confirmed successfully',
        user: result,
      };
    } catch {
      return { success: false, message: 'Failed to confirm email' };
    }
  }

  async resendConfirmationEmail(email: string): Promise<MessageResponseDto> {
    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.emailConfirmed) {
      throw new ConflictException('Email is already confirmed');
    }

    const rateLimitResult = await this.rateLimitingService.checkEmailAttempts(
      user._id.toString()
    );
    if (!rateLimitResult.allowed) {
      const waitMinutes = Math.ceil((rateLimitResult.waitTime ?? 0) / 60_000);
      throw new HttpException(
        `Please wait ${waitMinutes} minutes before requesting another confirmation email`,
        HttpStatus.TOO_MANY_REQUESTS
      );
    }

    await this.rateLimitingService.recordEmailAttempt(user._id.toString());

    const newEmailToken = this.generateEmailToken();
    const emailTokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const emailTokenGeneratedAt = new Date();
    user.emailToken = newEmailToken;
    user.emailTokenExpiresAt = emailTokenExpiresAt;
    user.emailTokenGeneratedAt = emailTokenGeneratedAt;
    await user.save();

    try {
      await this.emailService.sendConfirmationEmail(user.email, newEmailToken);
      return { message: 'Confirmation email sent successfully' };
    } catch (error) {
      await this.rateLimitingService.refundEmailAttempt(user._id.toString());
      this.logger.error('Failed to send confirmation email', error);
      throw new InternalServerErrorException(
        'Failed to send confirmation email. Please try again later.'
      );
    }
  }

  async fetchUser(userId: string): Promise<PrivateUserResponseDto> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('Your user profile could not be retrieved');
    }
    const privateUser: PrivateUserDto = {
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      birthdate: user.birthdate,
      dateJoined: user.createdAt,
      profilePicture: user.profilePicture,
      emailConfirmed: user.emailConfirmed,
      role: user.role,
      phoneNumber: user.phoneNumber,
      twoFactorEnabled: user.twoFactorEnabled,
    };

    return {
      message: 'User profile retrieved successfully',
      user: privateUser,
    };
  }

  async fetchUserById(
    userId: string,
    requester: { id: string; role: Role }
  ): Promise<PrivateUserResponseDto> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('The specified user could not be found');
    }

    const privateUser: PrivateUserDto = {
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      birthdate: user.birthdate,
      dateJoined: user.createdAt,
      profilePicture: user.profilePicture,
      emailConfirmed: user.emailConfirmed,
      role: user.role,
      phoneNumber: user.phoneNumber,
    };

    const canViewTwoFactorStatus =
      requester.id === user._id.toString() ||
      requester.role === Role.PLATFORM_ADMIN ||
      requester.role === Role.PLATFORM_OWNER;

    if (canViewTwoFactorStatus) {
      privateUser.twoFactorEnabled = user.twoFactorEnabled;
    }

    return {
      message: 'User retrieved successfully',
      user: privateUser,
    };
  }

  async fetchAllUsers(): Promise<UsersListResponseDto> {
    const users = await this.userModel.find().lean();

    const formatted = users.map(
      (u: User & { _id: Types.ObjectId; createdAt?: Date }) => ({
        id: u._id.toString(),
        username: u.username,
        email: u.email,
        firstName: u.firstName,
        lastName: u.lastName,
        birthdate: u.birthdate,
        profilePicture: u.profilePicture,
        phoneNumber: u.phoneNumber,
        role: u.role,
        dateJoined: u.createdAt,
        isBanned: u.isBanned ?? false,
        bannedReason: u.bannedReason,
      })
    );

    return {
      message: 'Users retrieved successfully',
      users: formatted,
    };
  }

  async updateUser(
    userId: string,
    updateDto: UpdateUserDto
  ): Promise<PrivateUserResponseDto> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('Your user profile could not be found');
    }

    const isEmailChanging = updateDto.email && updateDto.email !== user.email;
    const isPasswordChanging = !!updateDto.password;
    const hasLocalPassword = !!user.passwordHash;

    if (
      (isEmailChanging || isPasswordChanging) &&
      hasLocalPassword &&
      !updateDto.currentPassword
    ) {
      throw new UnauthorizedException(
        'Current password is required to update email or password'
      );
    }

    if (updateDto.currentPassword && hasLocalPassword) {
      const isPasswordValid = await compare(
        updateDto.currentPassword,
        user.passwordHash
      );
      if (!isPasswordValid) {
        throw new UnauthorizedException('Current password is incorrect');
      }
    }

    const updateData: Partial<User> = {};
    let hasUpdates = false;

    if (updateDto.username && updateDto.username !== user.username) {
      const existingUser = await this.userModel.findOne({
        username: updateDto.username,
      });
      if (existingUser) {
        throw new ConflictException('This username is already taken');
      }
      updateData.username = updateDto.username;
      hasUpdates = true;
    }

    if (updateDto.email && updateDto.email !== user.email) {
      const existingUser = await this.userModel.findOne({
        email: updateDto.email,
      });
      if (existingUser) {
        throw new ConflictException('This email is already registered');
      }
      updateData.email = updateDto.email;
      updateData.emailConfirmed = false;
      updateData.emailToken = this.generateEmailToken();
      hasUpdates = true;
    }

    if (updateDto.password) {
      try {
        updateData.passwordHash = await hash(updateDto.password, 10);
        hasUpdates = true;
      } catch {
        throw new BadRequestException('Unable to process password update');
      }
    }

    if (updateDto.firstName !== undefined) {
      updateData.firstName = updateDto.firstName;
      hasUpdates = true;
    }

    if (updateDto.lastName !== undefined) {
      updateData.lastName = updateDto.lastName;
      hasUpdates = true;
    }

    if (updateDto.birthdate) {
      const date = new Date(updateDto.birthdate);
      if (Number.isNaN(date.getTime())) {
        throw new BadRequestException('Invalid birthdate format');
      }
      updateData.birthdate = date;
      hasUpdates = true;
    }

    if (updateDto.phoneNumber !== undefined) {
      updateData.phoneNumber = updateDto.phoneNumber;
      hasUpdates = true;
    }

    if (updateDto.profilePicture !== undefined) {
      updateData.profilePicture = updateDto.profilePicture;
      hasUpdates = true;
    }

    if (!hasUpdates) {
      throw new BadRequestException('No update fields provided');
    }

    if (updateData.email && updateData.emailToken) {
      const originalEmail = user.email;
      const originalEmailConfirmed = user.emailConfirmed;

      const session = await this.connection.startSession();
      try {
        const updatedUser = await session.withTransaction(async () => {
          const userResult = await this.userModel.findByIdAndUpdate(
            userId,
            {
              email: updateData.email,
              emailToken: updateData.emailToken,
              emailConfirmed: false,
            },
            { returnDocument: 'after', session }
          );

          if (!userResult) {
            throw new BadRequestException('Failed to update user email');
          }

          return userResult;
        });

        try {
          await this.emailService.sendConfirmationEmail(
            updateData.email,
            updateData.emailToken
          );
        } catch (emailError) {
          await this.userModel.findByIdAndUpdate(userId, {
            $set: {
              email: originalEmail,
              emailConfirmed: originalEmailConfirmed,
            },
            $unset: { emailToken: '' },
          });
          this.logger.error(
            'Failed to send confirmation email, rolled back email change',
            emailError
          );
          throw new InternalServerErrorException(
            'Failed to send confirmation email. Email change was reverted. Please try again later.'
          );
        }

        delete updateData.email;
        delete updateData.emailToken;
        delete updateData.emailConfirmed;

        if (Object.keys(updateData).length === 0) {
          const publicUser: PrivateUserDto = {
            username: updatedUser.username,
            email: updatedUser.email,
            firstName: updatedUser.firstName,
            lastName: updatedUser.lastName,
            birthdate: updatedUser.birthdate,
            dateJoined: updatedUser.createdAt,
            profilePicture: updatedUser.profilePicture,
            emailConfirmed: updatedUser.emailConfirmed,
            role: updatedUser.role,
            twoFactorEnabled: updatedUser.twoFactorEnabled,
          };

          return {
            message: 'Profile updated successfully',
            user: publicUser,
          };
        }
      } catch (error) {
        if (error instanceof HttpException) {
          throw error;
        }
        this.logger.error('Failed to update user email', error);
        throw new InternalServerErrorException(
          'Failed to update email. Please try again later.'
        );
      } finally {
        await session.endSession();
      }
    }

    if (Object.keys(updateData).length > 0) {
      try {
        const updatedUser = await this.userModel.findByIdAndUpdate(
          userId,
          updateData,
          { returnDocument: 'after' }
        );

        if (!updatedUser) {
          throw new BadRequestException('Failed to update user');
        }

        const publicUser: PrivateUserDto = {
          username: updatedUser.username,
          email: updatedUser.email,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          birthdate: updatedUser.birthdate,
          dateJoined: updatedUser.createdAt,
          profilePicture: updatedUser.profilePicture,
          emailConfirmed: updatedUser.emailConfirmed,
          role: updatedUser.role,
          twoFactorEnabled: updatedUser.twoFactorEnabled,
        };

        return {
          message: 'Profile updated successfully',
          user: publicUser,
        };
      } catch (error) {
        if (error instanceof HttpException) {
          throw error;
        }
        throw new BadRequestException(
          'An error occurred while updating your profile'
        );
      }
    }

    const finalUser = await this.userModel.findById(userId);
    if (!finalUser) {
      throw new BadRequestException('Failed to retrieve updated user');
    }

    const publicUser: PrivateUserDto = {
      username: finalUser.username,
      email: finalUser.email,
      firstName: finalUser.firstName,
      lastName: finalUser.lastName,
      birthdate: finalUser.birthdate,
      dateJoined: finalUser.createdAt,
      profilePicture: finalUser.profilePicture,
      emailConfirmed: finalUser.emailConfirmed,
      role: finalUser.role,
      twoFactorEnabled: finalUser.twoFactorEnabled,
    };

    return {
      message:
        'Profile updated successfully. Please check your new email for confirmation.',
      user: publicUser,
    };
  }

  async deleteUser(userId: string): Promise<MessageResponseDto> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('Your user profile could not be found');
    }

    if (
      user.role === Role.PLATFORM_ADMIN ||
      user.role === Role.PLATFORM_OWNER
    ) {
      throw new ForbiddenException(
        'Admin accounts cannot be deleted via self-service'
      );
    }

    try {
      const businessUsers = await this.businessUserModel.find({ userId });
      const businessIds = businessUsers.map((bu) => bu.businessId);

      let tenantDatabasesCleaned = 0;
      if (businessIds.length > 0) {
        const businesses = await this.businessModel.find({
          _id: { $in: businessIds },
        });
        for (const business of businesses) {
          if (business.databaseName) {
            await this.tenantConnectionService.deactivateTenantUser(
              business.databaseName,
              userId,
              userId
            );
            tenantDatabasesCleaned++;
          }
        }
      }

      const businessUserDeleteResult = await this.businessUserModel.deleteMany({
        userId,
      });

      await this.userModel.findByIdAndDelete(userId);
      await this.auditEmitter.emitAction({
        action: AuditAction.USER_DELETED,
        userId: user._id.toString(),
        userEmail: user.email,
        userRole: user.role || 'USER',
        details: {
          method: 'self_delete',
          businessAssociationsRemoved: businessUserDeleteResult.deletedCount,
          tenantDatabasesCleaned,
        },
      });
      return { message: 'Account deleted successfully' };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new BadRequestException(
        'An error occurred while deleting your account'
      );
    }
  }

  async deleteUserByAdmin(
    adminId: string,
    userId: string
  ): Promise<MessageResponseDto> {
    if (adminId === userId) {
      throw new BadRequestException('Administrators cannot delete themselves');
    }

    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('The specified user could not be found');
    }

    const admin = await this.userModel.findById(adminId);
    if (!admin) {
      throw new NotFoundException('Admin not found');
    }

    if (
      admin.role === Role.PLATFORM_ADMIN &&
      user.role === Role.PLATFORM_OWNER
    ) {
      throw new ForbiddenException(
        'Platform admins cannot delete platform owners'
      );
    }

    const businessUsers = await this.businessUserModel.find({ userId });
    const businessIds = businessUsers.map((bu) => bu.businessId);

    let tenantDatabasesCleaned = 0;
    if (businessIds.length > 0) {
      const businesses = await this.businessModel.find({
        _id: { $in: businessIds },
      });
      for (const business of businesses) {
        if (business.databaseName) {
          await this.tenantConnectionService.deactivateTenantUser(
            business.databaseName,
            userId,
            adminId
          );
          tenantDatabasesCleaned++;
        }
      }
    }

    const businessUserDeleteResult = await this.businessUserModel.deleteMany({
      userId,
    });

    await this.userModel.deleteOne({ _id: userId });
    await this.auditEmitter.emitAction({
      action: AuditAction.USER_DELETED,
      userId: adminId,
      userEmail: admin.email ?? 'Unknown',
      userRole: admin.role || 'ADMIN',
      target: userId,
      details: {
        method: 'admin_deleted_user',
        businessAssociationsRemoved: businessUserDeleteResult.deletedCount,
        tenantDatabasesCleaned,
      },
    });
    return { message: 'User deleted successfully' };
  }

  async updateRefreshToken(
    userId: string,
    oldRefreshToken: string,
    refreshToken: string
  ): Promise<void> {
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await this.userModel.updateOne(
      { _id: userId },
      {
        $pull: {
          refreshTokens: {
            $or: [
              { expiresAt: { $lt: new Date() } },
              { token: oldRefreshToken },
            ],
          },
        },
      }
    );

    await this.userModel.updateOne(
      { _id: userId },
      {
        $push: {
          refreshTokens: {
            $each: [{ token: refreshToken, expiresAt }],
            $slice: -10,
          },
        },
      }
    );
  }

  generateTokens(user: User | TokenPayload): {
    accessToken: string;
    refreshToken: string;
  } {
    const isUser = '_id' in user;
    const userId = isUser
      ? String((user as Record<string, unknown>)._id)
      : String((user as Record<string, unknown>).id);

    const payload: TokenPayload = {
      sub: userId,
      id: userId,
      email: user.email ?? '',
      role: (user as User).role ?? '',
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
      jwtid: randomUUID(),
    });

    const refreshToken = this.jwtService.sign(
      { ...payload, type: 'refresh' },
      {
        expiresIn: '7d',
        jwtid: randomUUID(),
      }
    );

    return { accessToken, refreshToken };
  }

  private generateEmailToken(): string {
    return randomBytes(16).toString('hex');
  }

  async validateUser(
    email: string,
    password: string
  ): Promise<User | undefined> {
    const user = await this.userModel.findOne({ email });
    if (user && (await compare(password, user.passwordHash))) {
      return user;
    }
    return undefined;
  }

  private async handleFailedLogin(user: User): Promise<void> {
    user.failedLoginAttempts += 1;

    if (user.failedLoginAttempts >= 5) {
      user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
    }

    await user.save();
  }

  private async resetFailedAttempts(user: User): Promise<void> {
    if (user.failedLoginAttempts > 0 || user.lockUntil) {
      user.failedLoginAttempts = 0;
      user.lockUntil = undefined;
      await user.save();
    }
  }

  private resolveFrontendRedirectUri(
    requestedRedirectUri: string | undefined,
    lang: string
  ): string {
    const frontendUrl = process.env.FRONTEND_URL;
    if (!frontendUrl) {
      throw new InternalServerErrorException(
        'Service is temporarily unavailable'
      );
    }

    const fallback = new URL(`/${lang}/auth/callback`, frontendUrl).toString();
    if (!requestedRedirectUri) {
      return fallback;
    }

    try {
      const requested = new URL(requestedRedirectUri);
      const frontend = new URL(frontendUrl);
      if (requested.origin !== frontend.origin) {
        return fallback;
      }
      return requested.toString();
    } catch {
      return fallback;
    }
  }

  private async parseGoogleState(state: string): Promise<{
    mode: 'login' | 'register';
    lang: string;
    redirectUri: string;
  }> {
    await this.cleanupExpiredOAuthEntries();

    try {
      const decoded = this.jwtService.verify<Record<string, unknown>>(state);
      if (!this.isGoogleStateTokenPayload(decoded)) {
        throw new Error('invalid state');
      }
      const parsed = decoded;
      const consumed = await this.consumeGoogleStateNonce(parsed.nonce);
      if (!consumed) {
        throw new Error('invalid nonce');
      }

      const normalizedLang = this.normalizeLang(parsed.lang);

      return {
        mode: parsed.mode,
        lang: normalizedLang,
        redirectUri: this.resolveFrontendRedirectUri(
          parsed.redirectUri,
          normalizedLang
        ),
      };
    } catch (error) {
      if (
        error instanceof JsonWebTokenError ||
        (error instanceof Error &&
          (error.message === 'invalid state' ||
            error.message === 'invalid nonce'))
      ) {
        throw new BadRequestException('Invalid Google OAuth state');
      }

      throw new InternalServerErrorException({
        message: 'Failed to validate Google OAuth state',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private isGoogleStateTokenPayload(
    payload: unknown
  ): payload is GoogleStateTokenPayload {
    if (!payload || typeof payload !== 'object') {
      return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
      candidate.type === 'google-oauth-state' &&
      typeof candidate.mode === 'string' &&
      (candidate.mode === 'login' || candidate.mode === 'register') &&
      typeof candidate.lang === 'string' &&
      typeof candidate.redirectUri === 'string' &&
      typeof candidate.nonce === 'string'
    );
  }

  async exchangeGoogleOAuthCode(
    oauthCode: string
  ): Promise<AuthResponseDto | TwoFactorChallengeResponse> {
    await this.cleanupExpiredOAuthEntries();

    if (!oauthCode?.trim()) {
      throw new BadRequestException('OAuth code is required');
    }

    const payload = await this.consumeGoogleAuthCode(oauthCode);
    if (!payload) {
      throw new UnauthorizedException('OAuth code is invalid or expired');
    }

    return payload;
  }

  private async createGoogleOAuthCode(
    payload: AuthResponseDto | TwoFactorChallengeResponse
  ): Promise<string> {
    await this.cleanupExpiredOAuthEntries();

    const oauthCode = randomBytes(32).toString('base64url');
    await this.setGoogleAuthCode(oauthCode, {
      payload,
      expiresAt: Date.now() + AuthService.GOOGLE_AUTH_CODE_TTL_MS,
    });

    return oauthCode;
  }

  private async cleanupExpiredOAuthEntries(): Promise<void> {
    const now = Date.now();
    await this.ensureOAuthIndexes();

    const noncesCollection = this.connection.collection(
      AuthService.GOOGLE_STATE_NONCE_COLLECTION
    );
    const codesCollection = this.connection.collection(
      AuthService.GOOGLE_AUTH_CODE_COLLECTION
    );

    await Promise.all([
      noncesCollection.deleteMany({ expiresAt: { $lte: new Date(now) } }),
      codesCollection.deleteMany({ expiresAt: { $lte: new Date(now) } }),
    ]);
  }

  private normalizeLang(input: string | undefined): string {
    if (!input) {
      return 'en';
    }

    const trimmed = input.trim();
    if (!trimmed) {
      return 'en';
    }

    const parts = trimmed.replace('_', '-').split('-');
    const base = parts[0]?.toLowerCase() ?? 'en';
    const region = parts[1] ? parts[1].toUpperCase() : undefined;
    const normalized = region ? `${base}-${region}` : base;

    return AuthService.LANG_PATTERN.test(normalized) ? normalized : 'en';
  }

  private async ensureOAuthIndexes(): Promise<void> {
    if (this.oauthIndexesInitialized) {
      return;
    }

    const noncesCollection = this.connection.collection(
      AuthService.GOOGLE_STATE_NONCE_COLLECTION
    );
    const codesCollection = this.connection.collection(
      AuthService.GOOGLE_AUTH_CODE_COLLECTION
    );

    await Promise.all([
      noncesCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
      codesCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
      noncesCollection.createIndex({ nonce: 1 }, { unique: true }),
      codesCollection.createIndex({ code: 1 }, { unique: true }),
    ]);

    this.oauthIndexesInitialized = true;
  }

  private async setGoogleStateNonce(
    nonce: string,
    expiresAtMs: number
  ): Promise<void> {
    await this.ensureOAuthIndexes();
    const noncesCollection = this.connection.collection(
      AuthService.GOOGLE_STATE_NONCE_COLLECTION
    );

    await noncesCollection.updateOne(
      { nonce },
      {
        $set: {
          nonce,
          expiresAt: new Date(expiresAtMs),
        },
      },
      { upsert: true }
    );
  }

  private async consumeGoogleStateNonce(nonce: string): Promise<boolean> {
    await this.ensureOAuthIndexes();
    const noncesCollection = this.connection.collection(
      AuthService.GOOGLE_STATE_NONCE_COLLECTION
    );
    const result = await noncesCollection.deleteOne({
      nonce,
      expiresAt: { $gt: new Date() },
    });
    return result.deletedCount === 1;
  }

  private async setGoogleAuthCode(
    code: string,
    value: {
      payload: AuthResponseDto | TwoFactorChallengeResponse;
      expiresAt: number;
    }
  ): Promise<void> {
    await this.ensureOAuthIndexes();
    const codesCollection = this.connection.collection(
      AuthService.GOOGLE_AUTH_CODE_COLLECTION
    );

    await codesCollection.updateOne(
      { code },
      {
        $set: {
          code,
          payload: value.payload,
          expiresAt: new Date(value.expiresAt),
        },
      },
      { upsert: true }
    );
  }

  private async consumeGoogleAuthCode(
    code: string
  ): Promise<AuthResponseDto | TwoFactorChallengeResponse | undefined> {
    await this.ensureOAuthIndexes();
    const codesCollection = this.connection.collection(
      AuthService.GOOGLE_AUTH_CODE_COLLECTION
    );
    const result = await codesCollection.findOneAndDelete({
      code,
      expiresAt: { $gt: new Date() },
    });

    return result
      ? (result as unknown as GoogleAuthCodeRecord).payload
      : undefined;
  }

  private async findOrCreateGoogleUser(
    tokenInfo: GoogleTokenInfo
  ): Promise<User> {
    const existing = await this.userModel.findOne({ email: tokenInfo.email });
    if (existing) {
      if (!existing.emailConfirmed) {
        existing.emailConfirmed = true;
        existing.emailToken = undefined;
        await (existing as Document).save();
      }
      return existing;
    }

    const baseUsername = tokenInfo.email.split('@')[0] ?? 'accountia-user';
    const username = await this.generateUniqueUsername(baseUsername);
    const names = this.extractNames(tokenInfo);
    const randomPassword = randomBytes(32).toString('hex');
    const passwordHash = await hash(randomPassword, 10);

    const user = new this.userModel({
      username,
      email: tokenInfo.email,
      passwordHash,
      firstName: names.firstName,
      lastName: names.lastName,
      birthdate: new Date('2000-01-01T00:00:00.000Z'),
      phoneNumber: undefined,
      acceptTerms: true,
      profilePicture: tokenInfo.picture,
      emailConfirmed: true,
      emailToken: undefined,
    });

    await user.save();
    return user;
  }

  private extractNames(tokenInfo: GoogleTokenInfo): {
    firstName: string;
    lastName: string;
  } {
    const firstName = tokenInfo.given_name?.trim();
    const lastName = tokenInfo.family_name?.trim();
    if (firstName && lastName) {
      return { firstName, lastName };
    }

    const fullName = tokenInfo.name?.trim();
    if (fullName) {
      const [first, ...rest] = fullName.split(' ');
      return {
        firstName: first || 'Google',
        lastName: rest.join(' ') || 'User',
      };
    }

    return { firstName: 'Google', lastName: 'User' };
  }

  private async generateUniqueUsername(base: string): Promise<string> {
    const sanitized = base
      .toLowerCase()
      .replaceAll(/[^\d_a-z-]/g, '-')
      .replaceAll(/-+/g, '-')
      .slice(0, 20)
      .replaceAll(/^-+|-+$/g, '');

    const root =
      sanitized.length >= 5 ? sanitized : `user-${sanitized}`.slice(0, 20);

    let candidate = root;
    let attempts = 0;
    while (attempts < 20) {
      const existing = await this.userModel.findOne({ username: candidate });
      if (!existing) return candidate;

      attempts += 1;
      const suffix = `-${randomBytes(2).toString('hex')}`;
      candidate = `${root.slice(0, Math.max(5, 20 - suffix.length))}${suffix}`;
    }

    return `user-${randomBytes(4).toString('hex')}`;
  }

  async banUser(
    adminId: string,
    userId: string,
    reason?: string
  ): Promise<BanResponseDto> {
    if (adminId === userId) {
      throw new BadRequestException('You cannot ban yourself');
    }

    const [admin, user] = await Promise.all([
      this.userModel.findById(adminId),
      this.userModel.findById(userId),
    ]);

    if (!admin) throw new NotFoundException('Admin not found');
    if (!user) throw new NotFoundException('User not found');

    if (
      admin.role === Role.PLATFORM_ADMIN &&
      (user.role === Role.PLATFORM_OWNER || user.role === Role.PLATFORM_ADMIN)
    ) {
      throw new ForbiddenException(
        'Platform Admin cannot ban Platform Owner or Platform Admin'
      );
    }

    if (
      admin.role === Role.PLATFORM_OWNER &&
      user.role === Role.PLATFORM_OWNER
    ) {
      throw new ForbiddenException(
        'Platform Owner cannot ban another Platform Owner'
      );
    }

    if (user.isBanned) {
      throw new BadRequestException('User is already banned');
    }

    user.isBanned = true;
    user.bannedAt = new Date();
    user.bannedBy = adminId;
    user.bannedReason = reason;
    user.refreshTokens = [];
    await user.save();

    await this.auditEmitter.emitAction({
      action: AuditAction.BAN_USER,
      userId: adminId,
      userEmail: admin.email,
      userRole: admin.role || 'ADMIN',
      target: user.email,
      details: { targetUserId: userId, reason },
    });

    return {
      message: 'User banned successfully',
      userId: user._id.toString(),
      isBanned: true,
      reason,
    };
  }

  async unbanUser(adminId: string, userId: string): Promise<BanResponseDto> {
    if (adminId === userId) {
      throw new BadRequestException('You cannot unban yourself');
    }

    const [admin, user] = await Promise.all([
      this.userModel.findById(adminId),
      this.userModel.findById(userId),
    ]);

    if (!admin) throw new NotFoundException('Admin not found');
    if (!user) throw new NotFoundException('User not found');

    if (
      admin.role === Role.PLATFORM_ADMIN &&
      (user.role === Role.PLATFORM_OWNER || user.role === Role.PLATFORM_ADMIN)
    ) {
      throw new ForbiddenException(
        'Platform Admin cannot unban Platform Owner or Platform Admin'
      );
    }

    if (
      admin.role === Role.PLATFORM_OWNER &&
      user.role === Role.PLATFORM_OWNER
    ) {
      throw new ForbiddenException(
        'Platform Owner cannot unban another Platform Owner'
      );
    }

    if (!user.isBanned) {
      throw new BadRequestException('User is not banned');
    }

    user.isBanned = false;
    user.bannedAt = undefined;
    user.bannedBy = undefined;
    user.bannedReason = undefined;
    await user.save();

    await this.auditEmitter.emitAction({
      action: AuditAction.UNBAN_USER,
      userId: adminId,
      userEmail: admin.email ?? 'Unknown',
      userRole: admin.role || 'ADMIN',
      target: userId,
      details: { method: 'admin_unban' },
    });

    return {
      message: 'User ununbanned successfully',
      userId: user._id.toString(),
      isBanned: false,
    };
  }

  async changeUserRole(
    userId: string,
    newRole: Role,
    currentUser: UserPayload
  ): Promise<RoleResponseDto> {
    if (userId === currentUser.id)
      throw new ForbiddenException('You cannot change your own role');
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('User not found');
    const previousRole = user.role;
    if (
      currentUser.role === Role.PLATFORM_ADMIN &&
      previousRole === Role.PLATFORM_OWNER
    )
      throw new ForbiddenException(
        'Platform Admin cannot change Platform Owner role'
      );
    if (
      currentUser.role === Role.PLATFORM_ADMIN &&
      (newRole === Role.PLATFORM_OWNER || newRole === Role.PLATFORM_ADMIN)
    )
      throw new ForbiddenException(
        'Platform Admin cannot assign Platform Owner or Platform Admin roles'
      );

    user.role = newRole;
    await user.save();

    await this.auditEmitter.emitAction({
      action: AuditAction.ROLE_CHANGE,
      userId: currentUser.id,
      userEmail: currentUser.email ?? 'Unknown',
      userRole: currentUser.role ?? 'ADMIN',
      target: user._id.toString(),
      details: { previousRole, newRole },
    });

    return {
      message: 'User role updated successfully',
      userId: user._id.toString(),
      newRole: user.role,
      previousRole,
    };
  }

  async getStripeOnboardingLink(
    userId: string
  ): Promise<UserStripeOnboardingLinkDto> {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('User not found');

    if (!(user as User & { stripeConnectId?: string }).stripeConnectId) {
      const account = await this.stripe.accounts.create({
        type: 'express',
        email: user.email,
        capabilities: {
          card_payments: { requested: true },
          transfers: { requested: true },
        },
      });
      (user as User & { stripeConnectId?: string }).stripeConnectId =
        account.id;
      await user.save();
    }

    const accountLink = await this.stripe.accountLinks.create({
      account: (user as User & { stripeConnectId?: string }).stripeConnectId!,
      refresh_url: `${process.env.FRONTEND_URL}/en/invoices`,
      return_url: `${process.env.FRONTEND_URL}/en/invoices`,
      type: 'account_onboarding',
    });

    return {
      message: 'Stripe onboarding link generated',
      onboardingUrl: accountLink.url,
    };
  }

  async getStripeConnectStatus(
    userId: string
  ): Promise<UserStripeConnectStatusDto> {
    const user = await this.userModel.findById(userId);
    if (!user) return { isConnected: false, message: 'Account not found' };

    let isConnected = false;
    let message = 'Connect your Stripe account to start receiving payments.';

    if ((user as User & { stripeConnectId?: string }).stripeConnectId) {
      try {
        const account = await this.stripe.accounts.retrieve(
          (user as User & { stripeConnectId?: string }).stripeConnectId!
        );
        isConnected = account.charges_enabled;
        message = isConnected ? 'Connected' : 'Setup incomplete';
      } catch (error: unknown) {
        console.error(
          'Stripe error:',
          error instanceof Error ? error.message : String(error)
        );
        message = 'Stripe verification failed';
      }
    }

    return {
      isConnected,
      stripeConnectId: (user as User & { stripeConnectId?: string })
        .stripeConnectId,
      message,
    };
  }
}
