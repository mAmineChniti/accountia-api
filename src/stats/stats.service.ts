import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Revenue } from '../revenues/schemas/revenue.schema';
import { Expense } from '../expenses/schemas/expense.schema';
import { Model, Types } from 'mongoose';
import { type MonthlyAggregateResult } from '../common/types/aggregate.types';

@Injectable()
export class StatsService {
  constructor(
    @InjectModel(Revenue.name) private revenueModel: Model<Revenue>,
    @InjectModel(Expense.name) private expenseModel: Model<Expense>
  ) {}

  async getMonthlyStats(userId: string, year?: number) {
    if (!Types.ObjectId.isValid(userId)) {
      throw new BadRequestException('Invalid user ID format');
    }

    const currentYear = year ?? new Date().getFullYear();

    const revenues = await this.revenueModel.aggregate<MonthlyAggregateResult>([
      {
        $match: {
          user: new Types.ObjectId(userId),
          $expr: { $eq: [{ $year: '$date' }, currentYear] },
        },
      },
      {
        $group: {
          _id: { year: { $year: '$date' }, month: { $month: '$date' } },
          total: { $sum: '$amount' },
        },
      },
      { $sort: { '_id.month': 1 } },
    ]);

    const expenses = await this.expenseModel.aggregate<MonthlyAggregateResult>([
      {
        $match: {
          user: new Types.ObjectId(userId),
          $expr: { $eq: [{ $year: '$date' }, currentYear] },
        },
      },
      {
        $group: {
          _id: { year: { $year: '$date' }, month: { $month: '$date' } },
          total: { $sum: '$amount' },
        },
      },
      { $sort: { '_id.month': 1 } },
    ]);

    const months = [
      'Jan',
      'Feb',
      'Mar',
      'Apr',
      'May',
      'Jun',
      'Jul',
      'Aug',
      'Sep',
      'Oct',
      'Nov',
      'Dec',
    ];

    return months.map((month, index) => {
      const revenue =
        revenues.find((r) => r._id.month === index + 1)?.total ?? 0;
      const expense =
        expenses.find((e) => e._id.month === index + 1)?.total ?? 0;

      return {
        month,
        revenue,
        expenses: expense,
        profit: revenue - expense,
      };
    });
  }
}
