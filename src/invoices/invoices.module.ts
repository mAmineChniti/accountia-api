import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import {
  InvoiceIssuanceService,
  InvoiceReceiptService,
  RecipientResolutionService,
  InvoiceImportService,
} from './services';
import { InvoicesController } from './invoices.controller';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import {
  InvoiceReceipt,
  InvoiceReceiptSchema,
} from '@/invoices/schemas/invoice-receipt.schema';
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
import { ProductsModule } from '@/products/products.module';

@Module({
  imports: [
    EmailModule,
    NotificationsModule,
    ProductsModule,
    MongooseModule.forFeature([
      { name: Invoice.name, schema: InvoiceSchema },
      { name: InvoiceReceipt.name, schema: InvoiceReceiptSchema },
      { name: Product.name, schema: ProductSchema },
      { name: Business.name, schema: BusinessSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
      { name: User.name, schema: UserSchema },
    ]),
  ],
  providers: [
    InvoiceIssuanceService,
    InvoiceReceiptService,
    RecipientResolutionService,
    InvoiceImportService,
    TenantConnectionService,
    TenantContextService,
    TenantContextGuard,
  ],
  controllers: [InvoicesController],
  exports: [
    InvoiceIssuanceService,
    InvoiceReceiptService,
    InvoiceImportService,
  ],
})
export class InvoicesModule {}
