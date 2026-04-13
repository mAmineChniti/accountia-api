import { Injectable } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model, Types } from 'mongoose';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import { Expense, ExpenseSchema } from '@/expenses/schemas/expense.schema';
import {
  AnalyticsQueryDto,
  AnalyticsDashboardDto,
  FinancialSummaryDto,
  RevenueDataPointDto,
  AgingBucketDto,
  TopClientDto,
  CashFlowForecastDto,
} from './dto/analytics.dto';

@Injectable()
export class AnalyticsService {
  constructor(@InjectConnection() private connection: Connection) {}

  private getInvoiceModel(databaseName: string): Model<Invoice> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try { return tenantDb.model<Invoice>(Invoice.name); }
    catch { return tenantDb.model<Invoice>(Invoice.name, InvoiceSchema); }
  }

  private getExpenseModel(databaseName: string): Model<Expense> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try { return tenantDb.model<Expense>(Expense.name); }
    catch { return tenantDb.model<Expense>(Expense.name, ExpenseSchema); }
  }

  async getDashboard(
    businessId: string,
    databaseName: string,
    query: AnalyticsQueryDto
  ): Promise<AnalyticsDashboardDto> {
    const now = new Date();
    const startDate = query.startDate ? new Date(query.startDate) : new Date(now.getFullYear(), 0, 1);
    const endDate = query.endDate ? new Date(query.endDate) : now;

    const [summary, revenueTimeline, arAging, topClients, cashFlowForecast, expenseSummary] =
      await Promise.all([
        this.getFinancialSummary(businessId, databaseName, startDate, endDate),
        this.getRevenueTimeline(businessId, databaseName, startDate, endDate, query.groupBy),
        this.getArAging(businessId, databaseName),
        this.getTopClients(businessId, databaseName, startDate, endDate),
        this.getCashFlowForecast(businessId, databaseName),
        this.getExpenseSummary(businessId, databaseName, startDate, endDate),
      ]);

    return { summary, revenueTimeline, arAging, topClients, cashFlowForecast, expenseSummary };
  }

  private async getFinancialSummary(
    businessId: string,
    databaseName: string,
    startDate: Date,
    endDate: Date
  ): Promise<FinancialSummaryDto> {
    const invoiceModel = this.getInvoiceModel(databaseName);
    const now = new Date();
    const bId = new Types.ObjectId(businessId);

    const [paidAgg, outstandingAgg, overdueAgg, allAgg] = await Promise.all([
      invoiceModel.aggregate([
        { $match: { issuerBusinessId: bId, status: InvoiceStatus.PAID, issuedDate: { $gte: startDate, $lte: endDate } } },
        { $group: { _id: null, total: { $sum: '$totalAmount' }, count: { $sum: 1 } } },
      ]),
      invoiceModel.aggregate([
        { $match: { issuerBusinessId: bId, status: { $in: [InvoiceStatus.ISSUED, InvoiceStatus.VIEWED, InvoiceStatus.PARTIAL] } } },
        { $group: { _id: null, total: { $sum: { $subtract: ['$totalAmount', '$amountPaid'] } } } },
      ]),
      invoiceModel.aggregate([
        { $match: { issuerBusinessId: bId, status: InvoiceStatus.OVERDUE } },
        { $group: { _id: null, total: { $sum: { $subtract: ['$totalAmount', '$amountPaid'] } } } },
      ]),
      invoiceModel.aggregate([
        { $match: { issuerBusinessId: bId, issuedDate: { $gte: startDate, $lte: endDate } } },
        { $group: { _id: null, total: { $sum: '$totalAmount' }, count: { $sum: 1 }, avgDays: { $avg: { $subtract: [now, '$issuedDate'] } } } },
      ]),
    ]);

    const totalPaid = paidAgg[0]?.total ?? 0;
    const totalOutstanding = outstandingAgg[0]?.total ?? 0;
    const totalOverdue = overdueAgg[0]?.total ?? 0;
    const totalAll = allAgg[0]?.total ?? 0;
    const totalCount = allAgg[0]?.count ?? 0;

    return {
      totalRevenue: totalPaid,
      totalOutstanding,
      totalOverdue,
      totalPaid,
      averageInvoiceValue: totalCount > 0 ? totalAll / totalCount : 0,
      collectionRate: totalAll > 0 ? (totalPaid / totalAll) * 100 : 0,
      averageDaysToPay: allAgg[0]?.avgDays ? allAgg[0].avgDays / (1000 * 60 * 60 * 24) : 0,
      currency: 'TND',
    };
  }

  private async getRevenueTimeline(
    businessId: string,
    databaseName: string,
    startDate: Date,
    endDate: Date,
    groupBy = 'monthly'
  ): Promise<RevenueDataPointDto[]> {
    const invoiceModel = this.getInvoiceModel(databaseName);
    const bId = new Types.ObjectId(businessId);

    const dateFormat = groupBy === 'weekly'
      ? '%Y-W%V'
      : groupBy === 'yearly'
      ? '%Y'
      : '%Y-%m';

    const pipeline = [
      {
        $match: {
          issuerBusinessId: bId,
          issuedDate: { $gte: startDate, $lte: endDate },
          status: { $ne: InvoiceStatus.DRAFT },
        },
      },
      {
        $group: {
          _id: { $dateToString: { format: dateFormat, date: '$issuedDate' } },
          revenue: { $sum: '$totalAmount' },
          paid: { $sum: { $cond: [{ $eq: ['$status', InvoiceStatus.PAID] }, '$amountPaid', 0] } },
          unpaid: { $sum: { $cond: [{ $ne: ['$status', InvoiceStatus.PAID] }, { $subtract: ['$totalAmount', '$amountPaid'] }, 0] } },
          invoiceCount: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 as 1 } },
    ] as Parameters<typeof invoiceModel.aggregate>[0];

    const result = await invoiceModel.aggregate(pipeline);
    return result.map((item) => ({
      period: item._id,
      revenue: item.revenue,
      invoiceCount: item.invoiceCount,
      paid: item.paid,
      unpaid: item.unpaid,
    }));
  }

  private async getArAging(
    businessId: string,
    databaseName: string
  ): Promise<AgingBucketDto[]> {
    const invoiceModel = this.getInvoiceModel(databaseName);
    const now = new Date();

    const outstanding = await invoiceModel
      .find({
        issuerBusinessId: businessId,
        status: { $in: [InvoiceStatus.ISSUED, InvoiceStatus.VIEWED, InvoiceStatus.PARTIAL, InvoiceStatus.OVERDUE] },
      })
      .lean();

    const buckets = [
      { label: 'Current (0-30 days)', min: 0, max: 30, daysRange: '0-30' },
      { label: '31-60 days', min: 31, max: 60, daysRange: '31-60' },
      { label: '61-90 days', min: 61, max: 90, daysRange: '61-90' },
      { label: '90+ days', min: 91, max: Infinity, daysRange: '90+' },
    ];

    return buckets.map((bucket) => {
      const matching = outstanding.filter((inv) => {
        const daysPastDue = Math.max(0, Math.floor((now.getTime() - inv.dueDate.getTime()) / (1000 * 60 * 60 * 24)));
        return daysPastDue >= bucket.min && daysPastDue <= bucket.max;
      });
      return {
        label: bucket.label,
        daysRange: bucket.daysRange,
        amount: matching.reduce((sum, inv) => sum + (inv.totalAmount - (inv.amountPaid ?? 0)), 0),
        count: matching.length,
      };
    });
  }

  private async getTopClients(
    businessId: string,
    databaseName: string,
    startDate: Date,
    endDate: Date
  ): Promise<TopClientDto[]> {
    const invoiceModel = this.getInvoiceModel(databaseName);
    const bId = new Types.ObjectId(businessId);

    const result = await invoiceModel.aggregate([
      {
        $match: {
          issuerBusinessId: bId,
          status: { $ne: InvoiceStatus.DRAFT },
          issuedDate: { $gte: startDate, $lte: endDate },
        },
      },
      {
        $group: {
          _id: '$recipient.displayName',
          totalRevenue: { $sum: '$totalAmount' },
          invoiceCount: { $sum: 1 },
          lastInvoiceDate: { $max: '$issuedDate' },
        },
      },
      { $sort: { totalRevenue: -1 } },
      { $limit: 10 },
    ]);

    return result.map((item) => ({
      clientName: item._id ?? 'Unknown',
      totalRevenue: item.totalRevenue,
      invoiceCount: item.invoiceCount,
      avgDaysToPay: 0,
      lastInvoiceDate: item.lastInvoiceDate instanceof Date
        ? item.lastInvoiceDate.toISOString()
        : String(item.lastInvoiceDate),
    }));
  }

  private async getCashFlowForecast(
    businessId: string,
    databaseName: string
  ): Promise<CashFlowForecastDto[]> {
    const invoiceModel = this.getInvoiceModel(databaseName);
    const now = new Date();
    const ninetyDaysFromNow = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);

    const openInvoices = await invoiceModel
      .find({
        issuerBusinessId: businessId,
        status: { $in: [InvoiceStatus.ISSUED, InvoiceStatus.VIEWED, InvoiceStatus.PARTIAL, InvoiceStatus.OVERDUE] },
        dueDate: { $lte: ninetyDaysFromNow },
      })
      .sort({ dueDate: 1 })
      .lean();

    return openInvoices.map((inv) => ({
      date: inv.dueDate instanceof Date ? inv.dueDate.toISOString() : String(inv.dueDate),
      expectedInflow: inv.totalAmount - (inv.amountPaid ?? 0),
      invoiceNumber: inv.invoiceNumber,
      recipientName:
        (inv.recipient as { displayName?: string; email?: string })?.displayName ??
        (inv.recipient as { displayName?: string; email?: string })?.email ??
        'Unknown',
      status: inv.status,
    }));
  }

  private async getExpenseSummary(
    businessId: string,
    databaseName: string,
    startDate: Date,
    endDate: Date
  ): Promise<{ total: number; byCategory: Array<{ category: string; total: number }> }> {
    try {
      const expenseModel = this.getExpenseModel(databaseName);
      const bId = new Types.ObjectId(businessId);
      const result = await expenseModel.aggregate([
        { $match: { businessId: bId, expenseDate: { $gte: startDate, $lte: endDate } } },
        { $group: { _id: '$category', total: { $sum: '$amount' } } },
      ]);
      const total = result.reduce((sum, item) => sum + item.total, 0);
      return {
        total,
        byCategory: result.map((item) => ({ category: item._id, total: item.total })),
      };
    } catch {
      return { total: 0, byCategory: [] };
    }
  }
}
