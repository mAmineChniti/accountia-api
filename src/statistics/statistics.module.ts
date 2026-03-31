import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { StatisticsController } from './statistics.controller';
import { StatisticsService } from './statistics.service';
import { Transaction, TransactionSchema } from './schemas/transaction.schema';
import { User, UserSchema } from '@/users/schemas/user.schema';
import {
  BusinessApplication,
  BusinessApplicationSchema,
} from '@/business/schemas/business-application.schema';
import { AuditLog, AuditLogSchema } from './schemas/audit-log.schema';
import { AuthModule } from '@/auth/auth.module';
import { forwardRef } from '@nestjs/common';
import {
  RecurringInvoice,
  RecurringInvoiceSchema,
} from './schemas/recurring-invoice.schema';
import { RecurringInvoicesController } from './recurring-invoices.controller';
import { RecurringInvoicesService } from './recurring-invoices.service';
import { InvoiceCronService } from './invoice-cron.service';
import { BusinessModule } from '@/business/business.module';
import { Template, TemplateSchema } from './schemas/template.schema';
import { TemplatesController } from './templates.controller';
import { InvoicePdfService } from './invoice-pdf.service';

@Module({
  imports: [
    forwardRef(() => AuthModule),
    forwardRef(() => BusinessModule),
    MongooseModule.forFeature([
      { name: Transaction.name, schema: TransactionSchema },
      { name: User.name, schema: UserSchema },
      { name: BusinessApplication.name, schema: BusinessApplicationSchema },
      { name: AuditLog.name, schema: AuditLogSchema },
      { name: RecurringInvoice.name, schema: RecurringInvoiceSchema },
      { name: Template.name, schema: TemplateSchema },
    ]),
  ],
  controllers: [
    StatisticsController,
    RecurringInvoicesController,
    TemplatesController,
  ],
  providers: [
    StatisticsService,
    RecurringInvoicesService,
    InvoiceCronService,
    InvoicePdfService,
  ],
  exports: [StatisticsService],
})
export class StatisticsModule {}
