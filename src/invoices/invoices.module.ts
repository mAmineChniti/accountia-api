import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { InvoicesController } from './invoices.controller';
import { ManagedInvoicesController } from './managed-invoices.controller';
import { InvoicesService } from './invoices.service';
import { FlouciService } from './flouci.service';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import { AuthModule } from '@/auth/auth.module';
import { BusinessModule } from '@/business/business.module';
import { EmailModule } from '@/email/email.module';

@Module({
  imports: [
    AuthModule,
    BusinessModule,
    EmailModule,
    MongooseModule.forFeature([{ name: Invoice.name, schema: InvoiceSchema }]),
  ],
  controllers: [InvoicesController, ManagedInvoicesController],
  providers: [InvoicesService, FlouciService],
  exports: [InvoicesService, FlouciService],
})
export class InvoicesModule {}
