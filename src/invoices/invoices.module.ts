import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { InvoicesService } from './invoices.service';
import { InvoicesController } from './invoices.controller';
import {
  PersonalInvoice,
  PersonalInvoiceSchema,
} from '@/invoices/schemas/personal-invoice.schema';
import {
  CompanyInvoice,
  CompanyInvoiceSchema,
} from '@/invoices/schemas/company-invoice.schema';
import { Product, ProductSchema } from '@/products/schemas/product.schema';
import { Business, BusinessSchema } from '@/business/schemas/business.schema';
import {
  BusinessUser,
  BusinessUserSchema,
} from '@/business/schemas/business-user.schema';
import { User, UserSchema } from '@/users/schemas/user.schema';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import { TenantContextService } from '@/common/tenant/tenant-context.service';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { EmailModule } from '@/email/email.module';
import { NotificationsModule } from '@/notifications/notifications.module';

@Module({
  imports: [
    EmailModule,
    NotificationsModule,
    MongooseModule.forFeature([
      { name: PersonalInvoice.name, schema: PersonalInvoiceSchema },
      { name: CompanyInvoice.name, schema: CompanyInvoiceSchema },
      { name: Product.name, schema: ProductSchema },
      { name: Business.name, schema: BusinessSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
      { name: User.name, schema: UserSchema },
    ]),
  ],
  providers: [
    InvoicesService,
    TenantConnectionService,
    TenantContextService,
    TenantContextGuard,
  ],
  controllers: [InvoicesController],
  exports: [InvoicesService],
})
export class InvoicesModule {}
