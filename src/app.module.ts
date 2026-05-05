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
import { MetricsController } from './metrics.controller';
import { AnalyticsModule } from '@/analytics/analytics.module';
import { ClientPortalModule } from '@/client-portal/client-portal.module';
import { CollectionsModule } from '@/collections/collections.module';
import { CommentsModule } from '@/comments/comments.module';
import { ExpensesModule } from '@/expenses/expenses.module';
import { PurchaseOrdersModule } from '@/purchase-orders/purchase-orders.module';
import { RecurringInvoicesModule } from '@/recurring-invoices/recurring-invoices.module';
import { ReportsModule } from '@/reports/reports.module';
import { VendorsModule } from '@/vendors/vendors.module';
import { AlertsController } from './alerts.controller';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        MONGO_URI: Joi.string()
          .uri()
          .default('mongodb://localhost:27017/accountia'),
        JWT_SECRET: Joi.string().default(
          'default-jwt-secret-change-in-production'
        ),
        GMAIL_USERNAME: Joi.string().default('noreply@accountia.com'),
        GMAIL_APP_PASSWORD: Joi.string().default('default-app-password'),
        SMTP_HOST: Joi.string().default('smtp.gmail.com'),
        SMTP_PORT: Joi.number().default(587),
        FRONTEND_URL: Joi.string().uri().default('http://localhost:3000'),
        GROQ_API_KEY: Joi.string().default(''),
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
        STRIPE_SECRET_KEY: Joi.string().default('sk_test_default_key'),
        STRIPE_WEBHOOK_SECRET: Joi.string().default(
          'whsec_default_webhook_secret'
        ),
        STRIPE_FALLBACK_CURRENCY: Joi.string().default('USD'),
        STRIPE_FX_RATES: Joi.string().default('USD,EUR,GBP'),
        MOCK_INVOICE_PAYMENTS: Joi.boolean().default(true),
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
    AnalyticsModule,
    ClientPortalModule,
    CollectionsModule,
    CommentsModule,
    ExpensesModule,
    PurchaseOrdersModule,
    RecurringInvoicesModule,
    ReportsModule,
    VendorsModule,
  ],
  controllers: [MetricsController, AlertsController],
  providers: [],
})
export class AppModule {}
