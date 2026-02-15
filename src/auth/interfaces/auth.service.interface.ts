import { type User } from '@/users/schemas/user.schema';
import { type RegisterDto } from '@/auth/dto/register.dto';
import { type LoginDto } from '@/auth/dto/login.dto';
import { type RefreshTokenDto } from '@/auth/dto/refresh-token.dto';
import { type ForgotPasswordDto } from '@/auth/dto/forgot-password.dto';
import { type ResetPasswordDto } from '@/auth/dto/reset-password.dto';
import { type AuthResponseDto } from '@/auth/dto/auth-response.dto';

interface TokenPayload {
  id: string;
  email: string;
  username: string;
}

export interface IAuthService {
  register(registerDto: RegisterDto): Promise<AuthResponseDto>;
  login(loginDto: LoginDto, ip: string): Promise<AuthResponseDto>;
  logout(userId: string, refreshToken: string): Promise<void>;
  refreshTokens(refreshTokenDto: RefreshTokenDto): Promise<AuthResponseDto>;
  forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void>;
  resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void>;
  validateUser(email: string, password: string): Promise<User | undefined>;
  generateTokens(
    user: User | TokenPayload
  ): Promise<{ accessToken: string; refreshToken: string }>;
}
