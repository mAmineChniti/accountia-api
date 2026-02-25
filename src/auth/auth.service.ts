import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import type { JwtPayload } from 'jsonwebtoken';
import { hash, compare } from 'bcrypt';
import multiavatar from '@multiavatar/multiavatar';
import { randomBytes, randomUUID } from 'node:crypto';
import { User, UserDocument } from '@/users/schemas/user.schema';
import { RegisterDto } from '@/auth/dto/register.dto';
import { LoginDto } from '@/auth/dto/login.dto';
import { RefreshTokenDto } from '@/auth/dto/refresh-token.dto';
import { ForgotPasswordDto } from '@/auth/dto/forgot-password.dto';
import { ResetPasswordDto } from '@/auth/dto/reset-password.dto';
import { UpdateUserDto } from '@/auth/dto/update-user.dto';
import { AuthResponseDto } from '@/auth/dto/auth-response.dto';
import { RegistrationResponseDto } from '@/auth/dto/registration-response.dto';
import {
  PublicUserDto,
  UserResponseDto,
  MessageResponseDto,
} from '@/auth/dto/user-response.dto';
import { UsersListResponseDto } from '@/auth/dto/users-list.dto';
import { EmailService } from '@/auth/email.service';
import { RateLimitingService } from '@/auth/rate-limiting.service';

interface TokenPayload {
  sub?: string;
  id: string;
  email: string;
  username: string;
  isAdmin: boolean;
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
}

import { generateSecret, verify, generateURI } from 'otplib';

// eslint-disable-next-line @typescript-eslint/consistent-type-imports
let qrcodeModule: typeof import('qrcode') | undefined;

const getQrcode = async () => {
  qrcodeModule ??= await import('qrcode');
  return qrcodeModule;
};

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private emailService: EmailService,
    private rateLimitingService: RateLimitingService
  ) {}

  check2FAVerificationLimit(email: string, ip: string): void {
    const rateLimitResult = this.rateLimitingService.checkLoginAttempts(
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

  record2FAAttempt(email: string, ip: string, codeValid: boolean): void {
    if (codeValid) {
      this.rateLimitingService.clearLoginAttempts(email, ip);
    } else {
      this.rateLimitingService.recordFailedLogin(email, ip);
    }
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
    const isValid = result.valid;

    if (!isValid) return false;

    user.twoFactorSecret = user.twoFactorTempSecret;
    user.twoFactorEnabled = true;
    user.twoFactorTempSecret = undefined;
    await user.save();
    return true;
  }

  generateTempToken(user: UserDocument): string {
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

    this.check2FAVerificationLimit(user.email, ip);

    const result = await verify({ secret: user.twoFactorSecret, token: code });
    const isValid = result.valid;

    if (!isValid) {
      this.record2FAAttempt(user.email, ip, false);
      throw new UnauthorizedException('Invalid 2FA code');
    }

    this.record2FAAttempt(user.email, ip, true);
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
    user: UserDocument
  ): AuthResponseDto {
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
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        birthdate: user.birthdate,
        profilePicture: user.profilePicture,
        isAdmin: !!user.isAdmin,
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

    if (!acceptTerms) {
      throw new BadRequestException('You must accept the terms and conditions');
    }

    const existingUser = await this.userModel.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      const error = existingUser.emailConfirmed
        ? new ConflictException({
            type: 'ACCOUNT_EXISTS',
            message: 'Username or email is already registered',
          })
        : new ConflictException({
            type: 'EMAIL_NOT_CONFIRMED',
            message:
              'Account exists but email is not confirmed. Please check your email or request a new confirmation.',
            email: email,
          });
      throw error;
    }

    const passwordHash = await hash(password, 10);
    const emailToken = this.generateEmailToken();
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
        email,
        passwordHash,
        firstName,
        lastName,
        birthdate: birthdateDate,
        phoneNumber,
        acceptTerms,
        profilePicture: finalProfilePicture,
        emailToken,
        emailConfirmed: false,
        isAdmin: false,
      });

      await user.save();

      await this.emailService.sendConfirmationEmail(email, emailToken);

      return {
        message:
          'Registration successful! Please check your email to confirm your account.',
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
  ): Promise<
    AuthResponseDto | { tempToken: string; twoFactorRequired: boolean }
  > {
    const { email, password } = loginDto;
    const rateLimitResult = this.rateLimitingService.checkLoginAttempts(
      email,
      ip
    );
    if (!rateLimitResult.allowed) {
      throw new HttpException(
        'Too many failed login attempts. Please try again later.',
        HttpStatus.TOO_MANY_REQUESTS
      );
    }
    const user = await this.userModel.findOne({ email });
    if (!user) {
      this.rateLimitingService.recordFailedLogin(email, ip);
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
    const isPasswordValid = await compare(password, user.passwordHash);
    if (!isPasswordValid) {
      await this.handleFailedLogin(user);
      this.rateLimitingService.recordFailedLogin(email, ip);
      throw new UnauthorizedException('Invalid email or password');
    }
    if (user.twoFactorEnabled) {
      const tempToken = this.generateTempToken(user);
      return { tempToken, twoFactorRequired: true };
    }
    await this.resetFailedAttempts(user);
    this.rateLimitingService.clearLoginAttempts(email, ip);
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

  async logout(userId: string, refreshToken: string): Promise<void> {
    await this.userModel.updateOne(
      { _id: userId },
      { $pull: { refreshTokens: { token: refreshToken } } }
    );
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
  }

  async confirmEmail(
    token: string
  ): Promise<{ success: boolean; message: string }> {
    try {
      const user = await this.userModel.findOne({ emailToken: token });

      if (!user) {
        return { success: false, message: 'Invalid confirmation token' };
      }

      if (user.emailConfirmed) {
        return { success: false, message: 'Email is already confirmed' };
      }

      user.emailConfirmed = true;
      user.emailToken = undefined;
      user.emailConfirmationAttempts = 0;
      await user.save();

      return { success: true, message: 'Email confirmed successfully' };
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

    const rateLimitResult = this.rateLimitingService.checkEmailAttempts(
      user._id.toString()
    );
    if (!rateLimitResult.allowed) {
      const waitMinutes = Math.ceil((rateLimitResult.waitTime ?? 0) / 60_000);
      throw new HttpException(
        `Please wait ${waitMinutes} minutes before requesting another confirmation email`,
        HttpStatus.TOO_MANY_REQUESTS
      );
    }

    const newEmailToken = this.generateEmailToken();
    user.emailToken = newEmailToken;
    await user.save();

    try {
      await this.emailService.sendConfirmationEmail(user.email, newEmailToken);
      this.rateLimitingService.recordEmailAttempt(user._id.toString());
      return { message: 'Confirmation email sent successfully' };
    } catch {
      throw new BadRequestException('Unable to resend confirmation email');
    }
  }

  async fetchUser(userId: string): Promise<UserResponseDto> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('Your user profile could not be retrieved');
    }

    const publicUser: PublicUserDto = {
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      birthdate: user.birthdate,
      dateJoined: user.createdAt,
      profilePicture: user.profilePicture,
      emailConfirmed: user.emailConfirmed,
    };

    return {
      message: 'User profile retrieved successfully',
      user: publicUser,
    };
  }

  async fetchUserById(userId: string): Promise<UserResponseDto> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('The specified user could not be found');
    }

    const publicUser: PublicUserDto = {
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      birthdate: user.birthdate,
      dateJoined: user.createdAt,
      profilePicture: user.profilePicture,
      emailConfirmed: user.emailConfirmed,
    };

    return {
      message: 'User fetched successfully',
      user: publicUser,
    };
  }

  async fetchAllUsers(): Promise<UsersListResponseDto> {
    const users = await this.userModel.find().lean();

    const formatted = users.map((u) => ({
      id: u._id.toString(),
      username: u.username,
      email: u.email,
      firstName: u.firstName,
      lastName: u.lastName,
      birthdate: u.birthdate,
      profilePicture: u.profilePicture,
      phoneNumber: u.phoneNumber,
      isAdmin: !!u.isAdmin,
      dateJoined: u.createdAt,
    }));

    return {
      message: 'Users retrieved successfully',
      users: formatted,
    };
  }

  async updateUser(
    userId: string,
    updateDto: UpdateUserDto
  ): Promise<UserResponseDto> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('Your user profile could not be found');
    }

    const updateData: Partial<User> = {};
    let hasUpdates = false;

    if (updateDto.username && updateDto.username !== user.username) {
      const existingUser = await this.userModel.findOne({
        username: updateDto.username,
      });
      if (existingUser) {
        throw new ConflictException('Username is already taken');
      }
      updateData.username = updateDto.username;
      hasUpdates = true;
    }

    if (updateDto.email && updateDto.email !== user.email) {
      const existingUser = await this.userModel.findOne({
        email: updateDto.email,
      });
      if (existingUser) {
        throw new ConflictException('Email is already registered');
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

    try {
      const updatedUser = await this.userModel.findByIdAndUpdate(
        userId,
        updateData,
        { new: true }
      );

      if (!updatedUser) {
        throw new BadRequestException('Failed to update user');
      }

      if (updateData.email && updateData.emailToken) {
        try {
          await this.emailService.sendConfirmationEmail(
            updateData.email,
            updateData.emailToken
          );
        } catch (error) {
          console.error('Failed to send confirmation email:', error);
        }
      }

      const publicUser: PublicUserDto = {
        username: updatedUser.username,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        birthdate: updatedUser.birthdate,
        dateJoined: updatedUser.createdAt,
        profilePicture: updatedUser.profilePicture,
        emailConfirmed: updatedUser.emailConfirmed,
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

  async deleteUser(userId: string): Promise<MessageResponseDto> {
    try {
      const result = await this.userModel.findByIdAndDelete(userId);

      if (!result) {
        throw new BadRequestException('Failed to delete user');
      }

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

    await this.userModel.deleteOne({ _id: userId });
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
    const userId =
      user instanceof User && '_id' in user
        ? (user as UserDocument)._id.toString()
        : (user as TokenPayload).id;
    const payload: TokenPayload = {
      sub: userId,
      id: userId,
      email: user.email,
      username: user.username,
      isAdmin: user.isAdmin,
      firstName: user.firstName,
      lastName: user.lastName,
      phoneNumber: user.phoneNumber,
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '24h',
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

    await (user as UserDocument).save();
  }

  private async resetFailedAttempts(user: User): Promise<void> {
    if (user.failedLoginAttempts > 0 || user.lockUntil) {
      user.failedLoginAttempts = 0;
      user.lockUntil = undefined;
      await (user as UserDocument).save();
    }
  }
}
