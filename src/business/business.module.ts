import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { BusinessController } from './business.controller';
import { BusinessService } from './business.service';
import { AuthModule } from '@/auth/auth.module';
import { Business, BusinessSchema } from './schemas/business.schema';
import {
  BusinessApplication,
  BusinessApplicationSchema,
} from './schemas/business-application.schema';
import {
  BusinessUser,
  BusinessUserSchema,
} from './schemas/business-user.schema';

@Module({
  imports: [
    AuthModule,
    MongooseModule.forFeature([
      { name: Business.name, schema: BusinessSchema },
      { name: BusinessApplication.name, schema: BusinessApplicationSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
    ]),
  ],
  controllers: [BusinessController],
  providers: [BusinessService],
  exports: [BusinessService],
})
export class BusinessModule {}
