import { Module, forwardRef } from '@nestjs/common';
import { AnalyticsService } from './analytics.service';
import { AnalyticsController } from './analytics.controller';
import { BusinessModule } from '@/business/business.module';

@Module({
  imports: [forwardRef(() => BusinessModule)],
  providers: [AnalyticsService],
  controllers: [AnalyticsController],
  exports: [AnalyticsService],
})
export class AnalyticsModule {}
