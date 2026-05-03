import { Module, forwardRef } from '@nestjs/common';
import { RecurringInvoicesService } from './recurring-invoices.service';
import { RecurringInvoicesController } from './recurring-invoices.controller';
import { BusinessModule } from '@/business/business.module';

@Module({
  imports: [forwardRef(() => BusinessModule)],
  providers: [RecurringInvoicesService],
  controllers: [RecurringInvoicesController],
  exports: [RecurringInvoicesService],
})
export class RecurringInvoicesModule {}
