import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { BusinessController } from '@/business/business.controller';
import { BusinessService } from '@/business/business.service';
import { AuthModule } from '@/auth/auth.module';
import { EmailModule } from '@/email/email.module';
import { Business, BusinessSchema } from '@/business/schemas/business.schema';
import {
  BusinessApplication,
  BusinessApplicationSchema,
} from '@/business/schemas/business-application.schema';
import {
  BusinessUser,
  BusinessUserSchema,
} from '@/business/schemas/business-user.schema';
import {
  BusinessInvitation,
  BusinessInvitationSchema,
} from '@/business/schemas/business-invitation.schema';
import { User, UserSchema } from '@/users/schemas/user.schema';
import { Product, ProductSchema } from '@/products/schemas/product.schema';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import { TenantContextService } from '@/common/tenant/tenant-context.service';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';

@Module({
  imports: [
    AuthModule,
    EmailModule,
    MongooseModule.forFeature([
      { name: Business.name, schema: BusinessSchema },
      { name: BusinessApplication.name, schema: BusinessApplicationSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
      { name: BusinessInvitation.name, schema: BusinessInvitationSchema },
      { name: User.name, schema: UserSchema },
      { name: Product.name, schema: ProductSchema },
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
