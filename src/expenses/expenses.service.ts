import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model, Types } from 'mongoose';
import {
  Expense,
  ExpenseSchema,
  ExpenseStatus,
} from './schemas/expense.schema';
import {
  CreateExpenseDto,
  UpdateExpenseDto,
  ReviewExpenseDto,
  ExpenseResponseDto,
  ExpenseListResponseDto,
  ExpenseSummaryDto,
} from './dto/expense.dto';

@Injectable()
export class ExpensesService {
  constructor(@InjectConnection() private connection: Connection) {}

  private getExpenseModel(databaseName: string): Model<Expense> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try {
      return tenantDb.model<Expense>(Expense.name);
    } catch {
      return tenantDb.model<Expense>(Expense.name, ExpenseSchema);
    }
  }

  async create(
    businessId: string,
    databaseName: string,
    dto: CreateExpenseDto,
    userId: string,
    userName: string
  ): Promise<ExpenseResponseDto> {
    const model = this.getExpenseModel(databaseName);
    const { businessId: _, ...data } = dto;
    void _;

    const expense = new model({
      businessId,
      ...data,
      submittedBy: userId,
      submittedByName: userName,
      status: ExpenseStatus.DRAFT,
    });
    await expense.save();
    return this.formatResponse(expense);
  }

  async findByBusiness(
    businessId: string,
    databaseName: string,
    page = 1,
    limit = 10,
    status?: string,
    category?: string,
    submittedBy?: string
  ): Promise<ExpenseListResponseDto> {
    const model = this.getExpenseModel(databaseName);
    const conditions: Record<string, unknown> = { businessId };
    if (status) conditions.status = status;
    if (category) conditions.category = category;
    if (submittedBy) conditions.submittedBy = submittedBy;

    const [total, expenses] = await Promise.all([
      model.countDocuments(conditions),
      model
        .find(conditions)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
    ]);

    return {
      expenses: (expenses as Expense[]).map((e) => this.formatResponse(e)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async findById(
    id: string,
    businessId: string,
    databaseName: string
  ): Promise<ExpenseResponseDto> {
    const model = this.getExpenseModel(databaseName);
    const expense = await model.findById(id);
    if (!expense) throw new NotFoundException('Expense not found');
    this.verifyAccess(String(expense.businessId), businessId);
    return this.formatResponse(expense);
  }

  async update(
    id: string,
    businessId: string,
    databaseName: string,
    dto: UpdateExpenseDto,
    userId: string
  ): Promise<ExpenseResponseDto> {
    const model = this.getExpenseModel(databaseName);
    const expense = await model.findById(id);
    if (!expense) throw new NotFoundException('Expense not found');
    this.verifyAccess(String(expense.businessId), businessId);

    if (expense.status !== ExpenseStatus.DRAFT) {
      throw new BadRequestException('Only draft expenses can be edited');
    }
    if (String(expense.submittedBy) !== userId) {
      throw new ForbiddenException('You can only edit your own expenses');
    }

    const { businessId: _, ...updateData } = dto;
    void _;
    const updated = await model.findByIdAndUpdate(id, updateData, {
      returnDocument: 'after',
      runValidators: true,
    });
    if (!updated) throw new NotFoundException('Expense not found');
    return this.formatResponse(updated);
  }

  async submit(
    id: string,
    businessId: string,
    databaseName: string,
    userId: string
  ): Promise<ExpenseResponseDto> {
    const model = this.getExpenseModel(databaseName);
    const expense = await model.findById(id);
    if (!expense) throw new NotFoundException('Expense not found');
    this.verifyAccess(String(expense.businessId), businessId);

    if (expense.status !== ExpenseStatus.DRAFT) {
      throw new BadRequestException('Only draft expenses can be submitted');
    }
    if (String(expense.submittedBy) !== userId) {
      throw new ForbiddenException('You can only submit your own expenses');
    }

    expense.status = ExpenseStatus.SUBMITTED;
    await expense.save();
    return this.formatResponse(expense);
  }

  async review(
    id: string,
    businessId: string,
    databaseName: string,
    dto: ReviewExpenseDto,
    reviewerId: string
  ): Promise<ExpenseResponseDto> {
    const model = this.getExpenseModel(databaseName);
    const expense = await model.findById(id);
    if (!expense) throw new NotFoundException('Expense not found');
    this.verifyAccess(String(expense.businessId), businessId);

    if (expense.status !== ExpenseStatus.SUBMITTED) {
      throw new BadRequestException('Only submitted expenses can be reviewed');
    }

    expense.status = dto.decision;
    expense.reviewedBy = reviewerId;
    expense.reviewNotes = dto.reviewNotes;
    expense.reviewedAt = new Date();
    await expense.save();
    return this.formatResponse(expense);
  }

  async markReimbursed(
    id: string,
    businessId: string,
    databaseName: string
  ): Promise<ExpenseResponseDto> {
    const model = this.getExpenseModel(databaseName);
    const expense = await model.findById(id);
    if (!expense) throw new NotFoundException('Expense not found');
    this.verifyAccess(String(expense.businessId), businessId);

    if (expense.status !== ExpenseStatus.APPROVED) {
      throw new BadRequestException(
        'Only approved expenses can be marked as reimbursed'
      );
    }

    expense.status = ExpenseStatus.REIMBURSED;
    expense.reimbursedAt = new Date();
    await expense.save();
    return this.formatResponse(expense);
  }

  async delete(
    id: string,
    businessId: string,
    databaseName: string,
    userId: string
  ): Promise<void> {
    const model = this.getExpenseModel(databaseName);
    const expense = await model.findById(id);
    if (!expense) throw new NotFoundException('Expense not found');
    this.verifyAccess(String(expense.businessId), businessId);

    if (expense.status !== ExpenseStatus.DRAFT) {
      throw new BadRequestException('Only draft expenses can be deleted');
    }
    if (String(expense.submittedBy) !== userId) {
      throw new ForbiddenException('You can only delete your own expenses');
    }

    await model.findByIdAndDelete(id);
  }

  async getSummary(
    businessId: string,
    databaseName: string
  ): Promise<ExpenseSummaryDto> {
    const model = this.getExpenseModel(databaseName);
    const businessObjectId = new Types.ObjectId(businessId);

    const [categoryAgg, statusAgg] = await Promise.all([
      model.aggregate([
        { $match: { businessId: businessObjectId } },
        {
          $group: {
            _id: '$category',
            total: { $sum: '$amount' },
            count: { $sum: 1 },
          },
        },
      ]),
      model.aggregate([
        { $match: { businessId: businessObjectId } },
        {
          $group: {
            _id: '$status',
            total: { $sum: '$amount' },
            count: { $sum: 1 },
          },
        },
      ]),
    ]);

    const pendingReview = await model.countDocuments({
      businessId,
      status: ExpenseStatus.SUBMITTED,
    });

    const totalAmount = categoryAgg.reduce((sum, item) => sum + item.total, 0);

    return {
      totalAmount,
      byCategory: categoryAgg.map((item) => ({
        category: item._id,
        total: item.total,
        count: item.count,
      })),
      byStatus: statusAgg.map((item) => ({
        status: item._id,
        total: item.total,
        count: item.count,
      })),
      pendingReview,
      currency: 'TND',
    };
  }

  private verifyAccess(
    expenseBusinessId: string,
    currentBusinessId: string
  ): void {
    if (expenseBusinessId !== currentBusinessId) {
      throw new ForbiddenException('Access denied');
    }
  }

  private formatResponse(expense: Expense): ExpenseResponseDto {
    return {
      id: String(expense._id),
      businessId: String(expense.businessId),
      submittedBy: String(expense.submittedBy),
      submittedByName: expense.submittedByName,
      title: expense.title,
      amount: expense.amount,
      currency: expense.currency ?? 'TND',
      category: expense.category,
      expenseDate:
        expense.expenseDate instanceof Date
          ? expense.expenseDate.toISOString()
          : String(expense.expenseDate),
      description: expense.description,
      vendor: expense.vendor,
      receiptBase64: expense.receiptBase64,
      receiptMimeType: expense.receiptMimeType,
      status: expense.status,
      reviewedBy: expense.reviewedBy ? String(expense.reviewedBy) : undefined,
      reviewNotes: expense.reviewNotes,
      reviewedAt: expense.reviewedAt?.toISOString(),
      reimbursedAt: expense.reimbursedAt?.toISOString(),
      isBillable: expense.isBillable ?? false,
      linkedInvoiceId: expense.linkedInvoiceId
        ? String(expense.linkedInvoiceId)
        : undefined,
      createdAt: expense.createdAt,
      updatedAt: expense.updatedAt,
    };
  }
}
