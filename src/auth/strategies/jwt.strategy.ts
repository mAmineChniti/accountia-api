import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { User } from '@/users/schemas/user.schema';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private configService: ConfigService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // Try to extract from Authorization header first
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        // Then try to extract from cookies
        (req: Request) => {
          const cookies = req.cookies as Record<string, string> | undefined;
          if (cookies?.accessToken) {
            return cookies.accessToken;
          }
          return;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow('JWT_SECRET'),
    });
  }

  async validate(payload: {
    jti: string;
    sub: string;
    email: string;
    username: string;
  }) {
    console.log('[JWT] Validating payload:', {
      sub: payload.sub,
      email: payload.email,
      username: payload.username,
    });

    const user = await this.userModel
      .findById(payload.sub)
      .select('-passwordHash -refreshTokens');

    console.log('[JWT] User found in DB:', {
      exists: !!user,
      isActive: user?.isActive,
    });

    if (!user) {
      console.error('[JWT] User not found in database for ID:', payload.sub);
      throw new UnauthorizedException('User not found');
    }

    if (!user.isActive) {
      console.error('[JWT] User is inactive for ID:', payload.sub);
      throw new UnauthorizedException('User account is inactive');
    }

    return {
      id: user._id.toString(),
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      phoneNumber: user.phoneNumber,
    };
  }
}
