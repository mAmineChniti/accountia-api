import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Revenue, RevenueDocument } from './schemas/revenue.schema';
import { Model, Types } from 'mongoose';

@Injectable()
export class RevenuesService {
  constructor(
    @InjectModel(Revenue.name)
    private revenueModel: Model<RevenueDocument>,
  ) { }

  create(data: any) {
    return this.revenueModel.create(data);
  }

  findByUser(userId: string) {
    return this.revenueModel.find({
      user: new Types.ObjectId(userId),
    });
  }

  async getAdminStatistics() {
    const result = await this.revenueModel.aggregate([
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