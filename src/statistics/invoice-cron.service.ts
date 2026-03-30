import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { RecurringInvoice, RecurringInvoiceDocument, RecurringStatus } from './schemas/recurring-invoice.schema';
import { RecurringInvoicesService } from './recurring-invoices.service';

@Injectable()
export class InvoiceCronService {
  private readonly logger = new Logger(InvoiceCronService.name);

  constructor(
    @InjectModel(RecurringInvoice.name) private recurringModel: Model<RecurringInvoiceDocument>,
    private readonly recurringService: RecurringInvoicesService,
  ) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleRecurringInvoices() {
    this.logger.log('Starting daily check for recurring invoices...');
    
    // Find all active recurring invoices where nextRunDate is today or in the past
    const now = new Date();
    
    const dueInvoices = await this.recurringModel.find({
      status: RecurringStatus.ACTIVE,
      nextRunDate: { $lte: now }
    }).exec();

    this.logger.log(`Found ${dueInvoices.length} recurring invoices due for generation.`);

    let successCount = 0;
    let failCount = 0;

    for (const invoiceConfig of dueInvoices) {
      try {
        await this.recurringService.generateInvoiceFromRecurring(invoiceConfig);
        successCount++;
        this.logger.log(`Generated invoice for schedule ${invoiceConfig._id} (Client: ${invoiceConfig.clientName})`);
      } catch (error) {
        failCount++;
        this.logger.error(`Failed to generate invoice for schedule ${invoiceConfig._id}:`, error);
      }
    }

    this.logger.log(`Finished processing recurring invoices. Success: ${successCount}, Failed: ${failCount}`);
  }
}
