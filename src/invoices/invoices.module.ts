import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { InvoicesController } from './invoices.controller';
import { ManagedInvoicesController } from './managed-invoices.controller';
import { ClientInvoicesController } from './client-invoices.controller';
import { InvoicesService } from './invoices.service';
import { FlouciService } from './flouci.service';
import { Invoice, InvoiceSchema } from '@/business/schemas/invoice.schema';
import { AuthModule } from '@/auth/auth.module';
import { BusinessModule } from '@/business/business.module';

@Module({
  imports: [
    AuthModule,
    BusinessModule,
    MongooseModule.forFeature([
      { name: Invoice.name, schema: InvoiceSchema },
    ]),
  ],
  controllers: [InvoicesController, ManagedInvoicesController, ClientInvoicesController],
  providers: [InvoicesService, FlouciService],
  exports: [InvoicesService, FlouciService],
})
export class InvoicesModule {}
