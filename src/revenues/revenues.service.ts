import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Revenue, RevenueDocument } from './schemas/revenue.schema';
import { Model, Types } from 'mongoose';
import { type CreateRevenueDto } from './dto/create-revenue.dto';
import { type AggregateResult } from '../common/types/aggregate.types';

@Injectable()
export class RevenuesService {
  constructor(
    @InjectModel(Revenue.name)
    private revenueModel: Model<RevenueDocument>
  ) {}

  create(data: CreateRevenueDto) {
    return this.revenueModel.create(data);
  }

  findByUser(userId: string) {
    if (!Types.ObjectId.isValid(userId)) {
      throw new BadRequestException('Invalid user ID format');
    }
    return this.revenueModel.find({
      user: new Types.ObjectId(userId),
    });
  }

  async getAdminStatistics() {
    const result = await this.revenueModel.aggregate<AggregateResult>([
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
