import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Cron } from '@nestjs/schedule';
import { Connection, Model } from 'mongoose';
import {
  RecurringInvoice,
  RecurringInvoiceSchema,
  RecurringStatus,
  RecurringFrequency,
  RecurringEndCondition,
} from './schemas/recurring-invoice.schema';
import {
  CreateRecurringInvoiceDto,
  UpdateRecurringInvoiceDto,
  RecurringInvoiceResponseDto,
  RecurringInvoiceListResponseDto,
} from './dto/recurring-invoice.dto';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';

@Injectable()
export class RecurringInvoicesService {
  constructor(@InjectConnection() private connection: Connection) {}

  private getRecurringModel(databaseName: string): Model<RecurringInvoice> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try {
      return tenantDb.model<RecurringInvoice>(RecurringInvoice.name);
    } catch {
      return tenantDb.model<RecurringInvoice>(
        RecurringInvoice.name,
        RecurringInvoiceSchema
      );
    }
  }

  private getInvoiceModel(databaseName: string): Model<Invoice> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try {
      return tenantDb.model<Invoice>(Invoice.name);
    } catch {
      return tenantDb.model<Invoice>(Invoice.name, InvoiceSchema);
    }
  }

  async create(
    businessId: string,
    databaseName: string,
    dto: CreateRecurringInvoiceDto,
    userId: string
  ): Promise<RecurringInvoiceResponseDto> {
    const model = this.getRecurringModel(databaseName);
    const { businessId: _, ...data } = dto;
    void _;

    const startDate = new Date(data.startDate);
    const schedule = new model({
      businessId,
      ...data,
      startDate,
      nextRunAt: startDate,
      occurrenceCount: 0,
      createdBy: userId,
      status: RecurringStatus.ACTIVE,
      generatedInvoiceIds: [],
    });
    await schedule.save();
    return this.formatResponse(schedule);
  }

  async findByBusiness(
    businessId: string,
    databaseName: string,
    page = 1,
    limit = 10
  ): Promise<RecurringInvoiceListResponseDto> {
    const model = this.getRecurringModel(databaseName);
    const [total, schedules] = await Promise.all([
      model.countDocuments({ businessId }),
      model
        .find({ businessId })
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
    ]);

    return {
      schedules: (schedules as RecurringInvoice[]).map((s) =>
        this.formatResponse(s)
      ),
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
  ): Promise<RecurringInvoiceResponseDto> {
    const model = this.getRecurringModel(databaseName);
    const schedule = await model.findById(id);
    if (!schedule)
      throw new NotFoundException('Recurring invoice schedule not found');
    this.verifyAccess(String(schedule.businessId), businessId);
    return this.formatResponse(schedule);
  }

  async update(
    id: string,
    businessId: string,
    databaseName: string,
    dto: UpdateRecurringInvoiceDto
  ): Promise<RecurringInvoiceResponseDto> {
    const model = this.getRecurringModel(databaseName);
    const schedule = await model.findById(id);
    if (!schedule)
      throw new NotFoundException('Recurring invoice schedule not found');
    this.verifyAccess(String(schedule.businessId), businessId);

    const { businessId: _, ...updateData } = dto;
    void _;
    const updated = await model.findByIdAndUpdate(id, updateData, {
      returnDocument: 'after',
      runValidators: true,
    });
    if (!updated)
      throw new NotFoundException('Recurring invoice schedule not found');
    return this.formatResponse(updated);
  }

  async delete(
    id: string,
    businessId: string,
    databaseName: string
  ): Promise<void> {
    const model = this.getRecurringModel(databaseName);
    const schedule = await model.findById(id);
    if (!schedule)
      throw new NotFoundException('Recurring invoice schedule not found');
    this.verifyAccess(String(schedule.businessId), businessId);
    await model.findByIdAndDelete(id);
  }

  @Cron('0 * * * *')
  async processSchedules(): Promise<void> {
    const mainDb = this.connection.useDb('Accountia', { useCache: true });
    let BusinessModel: Model<{ databaseName: string; status: string }>;
    try {
      BusinessModel = mainDb.model('Business') as unknown as Model<{
        databaseName: string;
        status: string;
      }>;
    } catch {
      return;
    }

    const businesses = await BusinessModel.find({ status: 'approved' }).lean();

    for (const business of businesses) {
      try {
        await this.processBusinessSchedules(
          String((business as unknown as { _id: unknown })._id),
          business.databaseName
        );
      } catch {
        // Continue processing other businesses
      }
    }
  }

  private async processBusinessSchedules(
    businessId: string,
    databaseName: string
  ): Promise<void> {
    const model = this.getRecurringModel(databaseName);
    const now = new Date();

    const dueSchedules = await model
      .find({
        businessId,
        status: RecurringStatus.ACTIVE,
        nextRunAt: { $lte: now },
      })
      .exec();

    for (const schedule of dueSchedules) {
      await this.generateInvoice(schedule, databaseName);
    }
  }

  private async generateInvoice(
    schedule: RecurringInvoice,
    databaseName: string
  ): Promise<void> {
    const invoiceModel = this.getInvoiceModel(databaseName);

    const issuedDate = new Date();
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + (schedule.dueDaysFromIssue ?? 30));

    const invoiceNumber = `REC-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;

    const invoice = new invoiceModel({
      issuerBusinessId: schedule.businessId,
      invoiceNumber,
      recipient: schedule.recipient,
      status: schedule.autoIssue ? InvoiceStatus.ISSUED : InvoiceStatus.DRAFT,
      totalAmount: schedule.totalAmount,
      currency: schedule.currency,
      amountPaid: 0,
      issuedDate,
      dueDate,
      lineItems: schedule.lineItems,
      description:
        schedule.description ??
        `Auto-generated from schedule: ${schedule.name}`,
      paymentTerms: schedule.paymentTerms,
    });
    await invoice.save();

    const nextRun = this.calculateNextRun(
      schedule.nextRunAt,
      schedule.frequency
    );
    const newCount = schedule.occurrenceCount + 1;

    let newStatus: RecurringStatus = RecurringStatus.ACTIVE;
    if (
      schedule.endCondition === RecurringEndCondition.AFTER_OCCURRENCES &&
      schedule.maxOccurrences !== undefined &&
      newCount >= schedule.maxOccurrences
    ) {
      newStatus = RecurringStatus.COMPLETED;
    } else if (
      schedule.endCondition === RecurringEndCondition.BY_DATE &&
      schedule.endDate &&
      nextRun > schedule.endDate
    ) {
      newStatus = RecurringStatus.COMPLETED;
    }

    await (schedule.constructor as Model<RecurringInvoice>).findByIdAndUpdate(
      schedule._id,
      {
        $push: { generatedInvoiceIds: invoice._id },
        $inc: { occurrenceCount: 1 },
        nextRunAt: nextRun,
        lastRunAt: new Date(),
        status: newStatus,
      }
    );
  }

  private calculateNextRun(
    currentRun: Date,
    frequency: RecurringFrequency
  ): Date {
    const next = new Date(currentRun);
    switch (frequency) {
      case RecurringFrequency.DAILY: {
        next.setDate(next.getDate() + 1);
        break;
      }
      case RecurringFrequency.WEEKLY: {
        next.setDate(next.getDate() + 7);
        break;
      }
      case RecurringFrequency.MONTHLY: {
        next.setMonth(next.getMonth() + 1);
        break;
      }
      case RecurringFrequency.QUARTERLY: {
        next.setMonth(next.getMonth() + 3);
        break;
      }
      case RecurringFrequency.YEARLY: {
        next.setFullYear(next.getFullYear() + 1);
        break;
      }
    }
    return next;
  }

  private verifyAccess(
    scheduleBusinessId: string,
    currentBusinessId: string
  ): void {
    if (scheduleBusinessId !== currentBusinessId) {
      throw new ForbiddenException('Access denied');
    }
  }

  private formatResponse(
    schedule: RecurringInvoice
  ): RecurringInvoiceResponseDto {
    return {
      id: String(schedule._id),
      businessId: String(schedule.businessId),
      name: schedule.name,
      frequency: schedule.frequency,
      status: schedule.status,
      startDate:
        schedule.startDate instanceof Date
          ? schedule.startDate.toISOString()
          : String(schedule.startDate),
      endCondition: schedule.endCondition,
      maxOccurrences: schedule.maxOccurrences,
      occurrenceCount: schedule.occurrenceCount,
      endDate: schedule.endDate?.toISOString(),
      nextRunAt:
        schedule.nextRunAt instanceof Date
          ? schedule.nextRunAt.toISOString()
          : String(schedule.nextRunAt),
      lastRunAt: schedule.lastRunAt?.toISOString(),
      lineItems: schedule.lineItems as never[],
      totalAmount: schedule.totalAmount,
      currency: schedule.currency,
      dueDaysFromIssue: schedule.dueDaysFromIssue,
      recipient: schedule.recipient,
      description: schedule.description,
      paymentTerms: schedule.paymentTerms,
      autoIssue: schedule.autoIssue,
      generatedInvoiceIds: schedule.generatedInvoiceIds.map(String),
      createdBy: schedule.createdBy ? String(schedule.createdBy) : undefined,
      createdAt: schedule.createdAt,
      updatedAt: schedule.updatedAt,
    };
  }
}
