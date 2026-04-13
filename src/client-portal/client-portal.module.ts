import { Module, forwardRef } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ClientPortalService } from './client-portal.service';
import { ClientPortalController } from './client-portal.controller';
import { PortalToken, PortalTokenSchema } from './schemas/portal-token.schema';
import { InvoiceReceipt, InvoiceReceiptSchema } from '@/invoices/schemas/invoice-receipt.schema';
import { BusinessModule } from '@/business/business.module';

@Module({
  imports: [
    forwardRef(() => BusinessModule),
    MongooseModule.forFeature([
      { name: PortalToken.name, schema: PortalTokenSchema },
      { name: InvoiceReceipt.name, schema: InvoiceReceiptSchema },
    ]),
  ],
  providers: [ClientPortalService],
  controllers: [ClientPortalController],
  exports: [ClientPortalService],
})
export class ClientPortalModule {}
