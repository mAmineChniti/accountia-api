import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { BusinessController } from '@/business/business.controller';
import { BusinessService } from '@/business/business.service';
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
  BusinessInvite,
  BusinessInviteSchema,
} from '@/business/schemas/business-invite.schema';
import { User, UserSchema } from '@/users/schemas/user.schema';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import { TenantContextService } from '@/common/tenant/tenant-context.service';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import { Product, ProductSchema } from '@/products/schemas/product.schema';
import { InvoicesModule } from '@/invoices/invoices.module';
@Module({
  imports: [
    EmailModule,
    InvoicesModule,
    MongooseModule.forFeature([
      { name: Business.name, schema: BusinessSchema },
      { name: Invoice.name, schema: InvoiceSchema },
      { name: Product.name, schema: ProductSchema },
      { name: BusinessApplication.name, schema: BusinessApplicationSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
      { name: BusinessInvite.name, schema: BusinessInviteSchema },
      { name: User.name, schema: UserSchema },
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
