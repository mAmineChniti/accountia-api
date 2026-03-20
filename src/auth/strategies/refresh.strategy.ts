import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { User } from '@/users/schemas/user.schema';

@Injectable()
export class RefreshStrategy extends PassportStrategy(Strategy, 'refresh') {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private configService: ConfigService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow('JWT_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(
    req: Request,
    payload: {
      jti: string;
      sub: string;
      type?: string;
    }
  ) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new BadRequestException('Invalid token format');
    }

    // Verify token type is 'refresh'
    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('Invalid token type');
    }

    const rawToken = authHeader.slice(7);

    const user = await this.userModel.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found or inactive');
    }

    if (user.isBanned) {
      throw new UnauthorizedException('Your account has been banned');
    }

    const tokenExists = user.refreshTokens.some(
      (rt) => rt.token === rawToken && rt.expiresAt > new Date()
    );

    if (!tokenExists) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    return {
      id: user._id.toString(),
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      phoneNumber: user.phoneNumber,
      role: user.role,
    };
  }
}
