import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import * as Joi from 'joi';
import { AuthModule } from '@/auth/auth.module';

@Module({
  imports: [
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
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
