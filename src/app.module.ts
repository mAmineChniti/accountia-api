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
import { ReportsModule } from '@/reports/reports.module';
import { CommentsModule } from '@/comments/comments.module';
import { ExpensesModule } from '@/expenses/expenses.module';
import { RecurringInvoicesModule } from '@/recurring-invoices/recurring-invoices.module';
import { AnalyticsModule } from '@/analytics/analytics.module';
import { VendorsModule } from '@/vendors/vendors.module';
import { PurchaseOrdersModule } from '@/purchase-orders/purchase-orders.module';
import { ClientPortalModule } from '@/client-portal/client-portal.module';

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
        OPENROUTER_API_KEY: Joi.string().required(),
        OPENROUTER_MODEL: Joi.string().default('google/gemini-2.5-flash'),
        OPENROUTER_MAX_COMPLETION_TOKENS: Joi.number()
          .integer()
          .min(64)
          .max(16_000)
          .default(1200),
        OPENROUTER_TIMEOUT_MS: Joi.number()
          .integer()
          .min(1000)
          .max(120_000)
          .default(30_000),
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
    InvoicesModule,
    ReportsModule,
    CommentsModule,
    ExpensesModule,
    RecurringInvoicesModule,
    AnalyticsModule,
    VendorsModule,
    PurchaseOrdersModule,
    ClientPortalModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
