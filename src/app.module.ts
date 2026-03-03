import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import * as Joi from 'joi';
import { AuthModule } from '@/auth/auth.module';
import { StatsModule } from './stats/stats.module';
import { RevenuesModule } from './revenues/revenues.module';
import { ExpensesModule } from './expenses/expenses.module';
@Module({
  imports: [
    // Configuration globale avec validation
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

    // Connexion à MongoDB
    MongooseModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        uri: config.getOrThrow<string>('MONGO_URI'),
      }),
    }),

    // Modules de l'application
    AuthModule,
    StatsModule,
   
  RevenuesModule,
  ExpensesModule,
  StatsModule ,// ajout du module stats si tu veux l'utiliser
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}