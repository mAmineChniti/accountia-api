import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { BusinessController } from '@/business/business.controller';
import { BusinessService } from '@/business/business.service';
import { AuthModule } from '@/auth/auth.module';
import { Business, BusinessSchema } from '@/business/schemas/business.schema';
import {
  BusinessApplication,
  BusinessApplicationSchema,
} from '@/business/schemas/business-application.schema';
import {
  BusinessUser,
  BusinessUserSchema,
} from '@/business/schemas/business-user.schema';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import { TenantContextService } from '@/common/tenant/tenant-context.service';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';

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
  providers: [
    BusinessService,
    TenantConnectionService,
    TenantContextService,
    TenantContextGuard,
  ],
  exports: [
    BusinessService,
    TenantConnectionService,
    TenantContextService,
    TenantContextGuard,
  ],
})
export class BusinessModule {}
