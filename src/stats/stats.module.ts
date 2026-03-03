import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Revenue, RevenueSchema } from '../revenues/schemas/revenue.schema';
import { Expense, ExpenseSchema } from '../expenses/schemas/expense.schema';
import { StatsService } from './stats.service';
import { StatsController } from './stats.controller';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Revenue.name, schema: RevenueSchema },
      { name: Expense.name, schema: ExpenseSchema },
    ]),
  ],
  controllers: [StatsController],
  providers: [StatsService],
})
export class StatsModule {}