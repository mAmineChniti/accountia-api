import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Expense, ExpenseDocument } from './schemas/expense.schema';
import { Model, Types } from 'mongoose';
import { type CreateExpenseDto } from './dto/create-expense.dto';
import { type AggregateResult } from '../common/types/aggregate.types';

@Injectable()
export class ExpensesService {
  constructor(
    @InjectModel(Expense.name)
    private ExpenseModel: Model<ExpenseDocument>
  ) {}

  create(data: CreateExpenseDto) {
    return this.ExpenseModel.create(data);
  }

  findByUser(userId: string) {
    if (!Types.ObjectId.isValid(userId)) {
      throw new BadRequestException('Invalid user ID format');
    }
    return this.ExpenseModel.find({
      user: new Types.ObjectId(userId), // 🔥 conversion ici
    });
  }

  async getAdminStatistics() {
    const result = await this.ExpenseModel.aggregate<AggregateResult>([
      {
        $group: {
          _id: undefined,
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
