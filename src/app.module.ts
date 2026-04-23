import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import * as Joi from 'joi';
import { AuthModule } from '@/auth/auth.module';
import { BusinessModule } from '@/business/business.module';
import { EmailModule } from '@/email/email.module';
import { AuditModule } from '@/audit/audit.module';
import { NotificationsModule } from '@/notifications/notifications.module';
import { ChatModule } from '@/chat/chat.module';

import { ScheduleModule } from '@nestjs/schedule';
import { ProductsModule } from '@/products/products.module';
import { InvoicesModule } from '@/invoices/invoices.module';
import { RedisModule } from '@/redis/redis.module';
import { AccountantModule } from '@/accountant/accountant.module';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        MONGO_URI: Joi.string().uri().required(),
        JWT_SECRET: Joi.string().required(),
        GMAIL_USERNAME: Joi.string().required(),
        GMAIL_APP_PASSWORD: Joi.string().required(),
        SMTP_HOST: Joi.string().required(),
        SMTP_PORT: Joi.number().required(),
        FRONTEND_URL: Joi.string().uri().required(),
        GROQ_API_KEY: Joi.string().required(),
        GROQ_MAX_COMPLETION_TOKENS: Joi.number()
          .integer()
          .min(64)
          .max(16_000)
          .default(1200),
        GROQ_TIMEOUT_MS: Joi.number()
          .integer()
          .min(1000)
          .max(120_000)
          .default(30_000),
        STRIPE_SECRET_KEY: Joi.string().required(),
        STRIPE_WEBHOOK_SECRET: Joi.string().required(),
        STRIPE_FALLBACK_CURRENCY: Joi.string().required(),
        STRIPE_FX_RATES: Joi.string().required(),
        MOCK_INVOICE_PAYMENTS: Joi.boolean().required(),
        REDIS_URL: Joi.string().uri().default('redis://localhost:6379'),
        REDIS_TLS_REJECT_UNAUTHORIZED: Joi.boolean().default(false),
        // AI Accountant Service (optional - will warn if not configured)
        AI_ACCOUNTANT_URL: Joi.string().uri().default('http://localhost:8000'),
        AI_ACCOUNTANT_API_KEY: Joi.string().allow('').default(''),
      }),
    }),

    MongooseModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        uri: config.getOrThrow<string>('MONGO_URI'),
      }),
    }),

    AuthModule,
    BusinessModule,
    EmailModule,
    AuditModule,
    NotificationsModule,
    ChatModule,
    ProductsModule,
    RedisModule,
    InvoicesModule,
    AccountantModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
