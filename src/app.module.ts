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
import { InvoicesModule } from '@/invoices/invoices.module';

import { ScheduleModule } from '@nestjs/schedule';

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
    InvoicesModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
