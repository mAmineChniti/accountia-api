import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Revenue } from '../revenues/schemas/revenue.schema';
import { Expense } from '../expenses/schemas/expense.schema';
import { Model, Types } from 'mongoose';

@Injectable()
export class StatsService {
  constructor(
    @InjectModel(Revenue.name) private revenueModel: Model<Revenue>,
    @InjectModel(Expense.name) private expenseModel: Model<Expense>,
  ) {}

  async getMonthlyStats(userId: string) {
    const revenues = await this.revenueModel.aggregate([
      { $match: { user: new Types.ObjectId(userId) } },
      {
        $group: {
          _id: { $month: '$date' },
          total: { $sum: '$amount' },
        },
      },
    ]);

    const expenses = await this.expenseModel.aggregate([
      { $match: { user: new Types.ObjectId(userId) } },
      {
        $group: {
          _id: { $month: '$date' },
          total: { $sum: '$amount' },
        },
      },
    ]);

    const months = [
      'Jan','Feb','Mar','Apr','May','Jun',
      'Jul','Aug','Sep','Oct','Nov','Dec'
    ];

    return months.map((month, index) => {
      const revenue = revenues.find(r => r._id === index + 1)?.total || 0;
      const expense = expenses.find(e => e._id === index + 1)?.total || 0;

      return {
        month,
        revenue,
        expenses: expense,
        profit: revenue - expense,
      };
    });
  }
}