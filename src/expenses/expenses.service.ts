import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Expense, ExpenseDocument } from './schemas/expense.schema';
import { Model, Types } from 'mongoose';

@Injectable()
export class ExpensesService {
  constructor(
    @InjectModel(Expense.name)
    private ExpenseModel: Model<ExpenseDocument>,
  ) { }

  create(data: any) {
    return this.ExpenseModel.create(data);
  }

  findByUser(userId: string) {
    return this.ExpenseModel.find({
      user: new Types.ObjectId(userId),   // 🔥 conversion ici
    });
  }

  async getAdminStatistics() {
    const result = await this.ExpenseModel.aggregate([
      {
        $group: {
          _id: null,
          totalAmount: { $sum: '$amount' },
          count: { $sum: 1 },
        },
      },
    ]);
    if (result.length > 0) {
      return {
        totalAmount: result[0].totalAmount,
        count: result[0].count,
      };
    }
    return { totalAmount: 0, count: 0 };
  }
}