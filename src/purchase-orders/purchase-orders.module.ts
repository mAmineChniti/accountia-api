import { Module, forwardRef } from '@nestjs/common';
import { PurchaseOrdersService } from './purchase-orders.service';
import { PurchaseOrdersController } from './purchase-orders.controller';
import { BusinessModule } from '@/business/business.module';
import { VendorsModule } from '@/vendors/vendors.module';

@Module({
  imports: [forwardRef(() => BusinessModule), VendorsModule],
  providers: [PurchaseOrdersService],
  controllers: [PurchaseOrdersController],
  exports: [PurchaseOrdersService],
})
export class PurchaseOrdersModule {}
