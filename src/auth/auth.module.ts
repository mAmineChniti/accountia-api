import { Module, forwardRef } from '@nestjs/common';
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
import { GoogleStrategy } from '@/auth/strategies/google.strategy';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RefreshJwtGuard } from '@/auth/guards/refresh-jwt.guard';
import { AdminGuard } from '@/auth/guards/admin.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { GoogleAuthGuard } from '@/auth/guards/google-auth.guard';
import { GoogleCallbackGuard } from '@/auth/guards/google-callback.guard';
import { User, UserSchema } from '@/users/schemas/user.schema';

import { AdminSeederService } from '@/auth/admin-seeder.service';
import { StatisticsModule } from '@/statistics/statistics.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    forwardRef(() => StatisticsModule),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (cfg: ConfigService) => ({
        secret: cfg.get('JWT_SECRET'),
        signOptions: {
          expiresIn: '15m',
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
    GoogleStrategy,
    AdminSeederService,
    JwtAuthGuard,
    RefreshJwtGuard,
    AdminGuard,
    RolesGuard,
    GoogleAuthGuard,
    GoogleCallbackGuard,
  ],
  controllers: [AuthController],
  exports: [
    AuthService,
    EmailService,
    JwtStrategy,
    RefreshStrategy,
    GoogleStrategy,
    RateLimitingService,
    AdminSeederService,
    JwtAuthGuard,
    RefreshJwtGuard,
    AdminGuard,
    RolesGuard,
    GoogleAuthGuard,
    GoogleCallbackGuard,
  ],
})
export class AuthModule { }
