import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { RecurringInvoice, RecurringInvoiceDocument, RecurringStatus } from './schemas/recurring-invoice.schema';
import { CreateRecurringInvoiceDto, UpdateRecurringInvoiceStatusDto } from './dto/recurring-invoice.dto';
import { Transaction, TransactionDocument } from './schemas/transaction.schema';

@Injectable()
export class RecurringInvoicesService {
  constructor(
    @InjectModel(RecurringInvoice.name) private recurringModel: Model<RecurringInvoiceDocument>,
    @InjectModel(Transaction.name) private transactionModel: Model<TransactionDocument>,
  ) {}

  private calculateNextRunDate(startDate: Date, frequency: string): Date {
    const next = new Date(startDate);
    switch (frequency) {
      case 'daily':
        next.setDate(next.getDate() + 1);
        break;
      case 'weekly':
        next.setDate(next.getDate() + 7);
        break;
      case 'monthly':
        next.setMonth(next.getMonth() + 1);
        break;
      case 'quarterly':
        next.setMonth(next.getMonth() + 3);
        break;
      case 'annually':
        next.setFullYear(next.getFullYear() + 1);
        break;
    }
    return next;
  }

  async create(dto: CreateRecurringInvoiceDto): Promise<RecurringInvoiceDocument> {
    const startDate = new Date(dto.startDate);
    const endDate = dto.endDate ? new Date(dto.endDate) : undefined;
    
    // Determine next run date. If generateFirstImmediately is true, the first invoice is generated NOW,
    // so the nextRunDate should be one cycle in the future.
    let nextRunDate = startDate;
    if (dto.generateFirstImmediately) {
      nextRunDate = this.calculateNextRunDate(new Date(), dto.frequency);
    }
    
    // Ensure the start date isn't immediately overridden if not generating immediately
    // If startDate is in the past and we don't generate immediately, it might be due immediately.
    
    const recurring = new this.recurringModel({
      clientId: dto.clientId,
      clientName: dto.clientName,
      clientEmail: dto.clientEmail,
      items: dto.items,
      totalAmount: dto.totalAmount,
      frequency: dto.frequency,
      templateId: dto.templateId,
      startDate,
      endDate,
      nextRunDate,
      status: RecurringStatus.ACTIVE,
      autoSend: dto.autoSend || false,
    });

    const saved = await recurring.save();

    if (dto.generateFirstImmediately) {
      await this.generateInvoiceFromRecurring(saved);
    }

    return saved;
  }

  async findAll(): Promise<RecurringInvoiceDocument[]> {
    return this.recurringModel.find().sort({ createdAt: -1 }).exec();
  }

  async findOne(id: string): Promise<RecurringInvoiceDocument> {
    const recurring = await this.recurringModel.findById(id).exec();
    if (!recurring) {
      throw new NotFoundException(`Recurring invoice with ID ${id} not found`);
    }
    return recurring;
  }

  async updateStatus(id: string, dto: UpdateRecurringInvoiceStatusDto): Promise<RecurringInvoiceDocument> {
    const recurring = await this.recurringModel.findByIdAndUpdate(
      id,
      { status: dto.status },
      { new: true }
    ).exec();
    
    if (!recurring) {
      throw new NotFoundException(`Recurring invoice with ID ${id} not found`);
    }
    return recurring;
  }

  async remove(id: string): Promise<void> {
    const result = await this.recurringModel.deleteOne({ _id: id }).exec();
    if (result.deletedCount === 0) {
      throw new NotFoundException(`Recurring invoice with ID ${id} not found`);
    }
  }

  async getStats() {
    const activeCount = await this.recurringModel.countDocuments({ status: RecurringStatus.ACTIVE }).exec();
    const pausedCount = await this.recurringModel.countDocuments({ status: RecurringStatus.PAUSED }).exec();
    
    const revenueAggregation = await this.recurringModel.aggregate([
      { $match: { status: 'active' } },
      {
        $group: {
          _id: null,
          totalMrr: {
            $sum: {
              $cond: [
                { $eq: ["$frequency", "monthly"] }, "$totalAmount",
                { $cond: [
                  { $eq: ["$frequency", "annually"] }, { $divide: ["$totalAmount", 12] },
                  { $cond: [
                    { $eq: ["$frequency", "quarterly"] }, { $divide: ["$totalAmount", 3] },
                    { $cond: [
                      { $eq: ["$frequency", "weekly"] }, { $multiply: ["$totalAmount", 4.33] },
                      { $multiply: ["$totalAmount", 30] } // daily
                    ]}
                  ]}
                ]}
              ]
            }
          }
        }
      }
    ]).exec();

    return {
      activeCount,
      pausedCount,
      estimatedMrr: revenueAggregation[0]?.totalMrr || 0
    };
  }

  // Used by the background job or immediate generation
  async generateInvoiceFromRecurring(recurring: RecurringInvoiceDocument): Promise<void> {
    // 1. Create a Transaction linked to this recurring config
    const tx = new this.transactionModel({
      'Transaction ID': `REC-${Date.now()}`,
      'Date': new Date(),
      'Account Type': 'Revenue',
      'Transaction Amount': recurring.totalAmount,
      'Revenue': recurring.totalAmount,
      'Expenditure': 0,
      'originalCurrency': 'USD', // Assumes USD base for now
      'convertedCurrency': 'USD',
      'exchangeRate': 1,
      'convertedAmount': recurring.totalAmount,
      recurringInvoiceId: recurring._id, // we should add this to schema if tracking
      clientName: recurring.clientName,
    });

    await tx.save();

    // 2. Schedule next run
    const nextDate = this.calculateNextRunDate(recurring.nextRunDate, recurring.frequency);
    
    // Check if nextDate is past endDate
    if (recurring.endDate && nextDate > recurring.endDate) {
      recurring.status = RecurringStatus.CANCELLED;
    } else {
      recurring.nextRunDate = nextDate;
    }
    
    await recurring.save();

    // 3. Send email if autoSend is enabled
    if (recurring.autoSend && recurring.clientEmail) {
      // Use existing EmailService logic or event emitter here to decouple
      console.log(`[AutoSend] Emitting email intended for ${recurring.clientEmail}`);
    }
  }
}
