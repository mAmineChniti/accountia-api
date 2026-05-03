import { Module, forwardRef } from '@nestjs/common';
import { ExpensesService } from './expenses.service';
import { ExpensesController } from './expenses.controller';
import { ReceiptExtractionService } from './services/receipt-extraction.service';
import { BusinessModule } from '@/business/business.module';

@Module({
  imports: [forwardRef(() => BusinessModule)],
  providers: [ExpensesService, ReceiptExtractionService],
  controllers: [ExpensesController],
  exports: [ExpensesService],
})
export class ExpensesModule {}
