import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { BusinessApplicationController } from './business-application.controller';
import { BusinessApplicationService } from './business-application.service';
import {
  BusinessApplication,
  BusinessApplicationSchema,
} from './schemas/business-application.schema';
import { User, UserSchema } from '@/users/schemas/user.schema';
import { AuthModule } from '@/auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: BusinessApplication.name, schema: BusinessApplicationSchema },
      { name: User.name, schema: UserSchema },
    ]),
    AuthModule,
  ],
  controllers: [BusinessApplicationController],
  providers: [BusinessApplicationService],
  exports: [BusinessApplicationService],
})
export class BusinessApplicationModule {}