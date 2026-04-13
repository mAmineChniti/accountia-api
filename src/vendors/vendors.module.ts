import { Module, forwardRef } from '@nestjs/common';
import { VendorsService } from './vendors.service';
import { VendorsController } from './vendors.controller';
import { BusinessModule } from '@/business/business.module';

@Module({
  imports: [forwardRef(() => BusinessModule)],
  providers: [VendorsService],
  controllers: [VendorsController],
  exports: [VendorsService],
})
export class VendorsModule {}
