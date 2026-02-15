import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from '@/auth/auth.service';
import { AuthController } from '@/auth/auth.controller';
import { EmailService } from '@/auth/email.service';
import { RateLimitingService } from '@/auth/rate-limiting.service';
import { JwtStrategy } from '@/auth/strategies/jwt.strategy';
import { RefreshStrategy } from '@/auth/strategies/refresh.strategy';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RefreshJwtGuard } from '@/auth/guards/refresh-jwt.guard';
import { User, UserSchema } from '@/users/schemas/user.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (cfg: ConfigService) => ({
        secret: cfg.get('JWT_SECRET'),
        signOptions: {
          expiresIn: '24h',
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    AuthService,
    EmailService,
    RateLimitingService,
    JwtStrategy,
    RefreshStrategy,
    JwtAuthGuard,
    RefreshJwtGuard,
  ],
  controllers: [AuthController],
  exports: [
    AuthService,
    JwtStrategy,
    RefreshStrategy,
    RateLimitingService,
    JwtAuthGuard,
    RefreshJwtGuard,
  ],
})
export class AuthModule {}
