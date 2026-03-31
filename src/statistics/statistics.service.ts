import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Transaction, TransactionDocument } from './schemas/transaction.schema';
import { User, UserDocument } from '@/users/schemas/user.schema';
import {
  BusinessApplication,
  BusinessApplicationDocument,
} from '@/business/schemas/business-application.schema';
import { AuditLog, AuditLogDocument } from './schemas/audit-log.schema';
import { OnModuleInit } from '@nestjs/common';
import { TransactionQueryDto } from './dto/transaction-query.dto';
import { InvoicePdfService } from './invoice-pdf.service';

const calculateGrowth = (current: number, previous: number): number => {
  if (previous === 0) return current > 0 ? 100 : 0;
  return Number.parseFloat(
    (((current - previous) / previous) * 100).toFixed(1)
  );
};

@Injectable()
export class StatisticsService implements OnModuleInit {
  constructor(
    @InjectModel(Transaction.name)
    private transactionModel: Model<TransactionDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(BusinessApplication.name)
    private applicationModel: Model<BusinessApplicationDocument>,
    @InjectModel(AuditLog.name) private auditLogModel: Model<AuditLogDocument>,
    private readonly pdfService: InvoicePdfService
  ) {}

  async onModuleInit() {
    try {
      // Seed initial logs if none exist for demonstration
      const count = await Promise.race([
        this.auditLogModel.countDocuments(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('DB Timeout')), 5000)
        ),
      ]);

      if (count === 0) {
        const demoLogs = [
          {
            userId: 'system',
            username: 'System',
            action: 'CREATE',
            resource: 'User',
            details: { message: 'Admin dashboard initialized' },
            createdAt: new Date(),
          },
          {
            userId: 'admin',
            username: 'Admin',
            action: 'UPDATE',
            resource: 'Settings',
            details: { message: 'Platform constraints updated' },
            createdAt: new Date(Date.now() - 1000 * 60 * 5),
          },
          {
            userId: 'admin',
            username: 'Admin',
            action: 'DELETE',
            resource: 'User',
            details: { message: 'Test account removed' },
            createdAt: new Date(Date.now() - 1000 * 60 * 15),
          },
        ];
        await this.auditLogModel.insertMany(demoLogs);
      }
    } catch (error) {
      console.warn(
        'Audit logs seeding skipped or timed out:',
        (error as Error).message
      );
    }
  }

  async createLog(
    userId: string,
    username: string,
    action: string,
    resource: string,
    details?: Record<string, unknown>
  ) {
    const log = new this.auditLogModel({
      userId,
      username,
      action,
      resource,
      details,
    });
    return log.save();
  }

  async getAuditLogs(limit = 20) {
    return this.auditLogModel
      .find()
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
  }

  async getStatistics() {
    const kpisPipeline = [
      {
        $group: {
          _id: undefined,
          totalRevenue: { $sum: { $ifNull: ['$Revenue', '$revenue'] } },
          totalExpenditure: {
            $sum: { $ifNull: ['$Expenditure', '$expenditure'] },
          },
          netIncome: { $sum: { $ifNull: ['$Net Income', '$netIncome'] } },
          avgProfitMargin: {
            $avg: { $ifNull: ['$Profit Margin', '$profitMargin'] },
          },
          avgAccuracyScore: {
            $avg: { $ifNull: ['$Accuracy Score', '$accuracyScore'] },
          },
          totalTransactions: { $sum: 1 },
          successCount: {
            $sum: {
              $cond: [
                {
                  $eq: [
                    {
                      $ifNull: ['$Transaction Outcome', '$transactionOutcome'],
                    },
                    1,
                  ],
                },
                1,
                0,
              ],
            },
          },
        },
      },
    ];

    const kpiResults = await this.transactionModel.aggregate<{
      totalRevenue: number;
      totalExpenditure: number;
      netIncome: number;
      avgProfitMargin: number;
      avgAccuracyScore: number;
      totalTransactions: number;
      successCount: number;
    }>(kpisPipeline);
    const kpi = kpiResults[0] ?? {
      totalRevenue: 0,
      totalExpenditure: 0,
      netIncome: 0,
      avgProfitMargin: 0,
      avgAccuracyScore: 0,
      totalTransactions: 0,
      successCount: 0,
    };

    const successRate =
      kpi.totalTransactions > 0
        ? (kpi.successCount / kpi.totalTransactions) * 100
        : 0;

    const timeSeriesPipeline = [
      {
        $group: {
          _id: {
            month: { $month: { $toDate: { $ifNull: ['$Date', '$date'] } } },
            year: { $year: { $toDate: { $ifNull: ['$Date', '$date'] } } },
          },
          revenue: { $sum: { $ifNull: ['$Revenue', '$revenue'] } },
          expenditure: { $sum: { $ifNull: ['$Expenditure', '$expenditure'] } },
          netIncome: { $sum: { $ifNull: ['$Net Income', '$netIncome'] } },
        },
      },
      { $sort: { '_id.year': 1 as const, '_id.month': 1 as const } },
    ];

    const timeSeriesData = await this.transactionModel.aggregate<{
      _id: { month: number; year: number };
      revenue: number;
      expenditure: number;
      netIncome: number;
    }>(timeSeriesPipeline);
    const revenueVsExpenditure = timeSeriesData.map((item) => ({
      name: `${item._id.month}/${item._id.year}`,
      Revenue: item.revenue,
      Expenditure: item.expenditure,
      'Net Income': item.netIncome,
    }));

    const accountTypePipeline = [
      {
        $group: {
          _id: { $ifNull: ['$Account Type', '$accountType'] },
          count: { $sum: 1 },
          amount: { $sum: { $ifNull: ['$Transaction Amount', '$amount'] } },
        },
      },
    ];
    const accountTypeData = await this.transactionModel.aggregate<{
      _id: string;
      count: number;
      amount: number;
    }>(accountTypePipeline);

    const transactionsByAccountType = accountTypeData.map((item) => ({
      name: item._id ?? 'Unknown',
      value: item.count,
    }));

    const totalAmountByAccountType = accountTypeData.map((item) => ({
      name: item._id ?? 'Unknown',
      value: item.amount,
    }));

    const marginDistributionPipeline = [
      {
        $bucket: {
          groupBy: { $ifNull: ['$Profit Margin', '$profitMargin'] },
          boundaries: [0, 0.25, 0.5, 0.75, 1],
          default: 'Other',
          output: { count: { $sum: 1 } },
        },
      },
    ];

    // Fallback if there are no documents matching the bucket
    let marginData: { _id: number | string; count: number }[] = [];
    try {
      marginData = await this.transactionModel.aggregate<{
        _id: number | string;
        count: number;
      }>(marginDistributionPipeline);
    } catch {
      // Bucket can fail if no data
      marginData = [];
    }

    const profitMarginDistribution = marginData.map((item) => {
      let label = 'Other';
      switch (item._id) {
        case 0: {
          label = '0-25%';
          break;
        }
        case 0.25: {
          label = '25-50%';
          break;
        }
        case 0.5: {
          label = '50-75%';
          break;
        }
        case 0.75: {
          {
            label = '75-100%';
            // No default
          }
          break;
        }
      }
      return { name: label, value: item.count };
    });

    return {
      kpis: {
        totalRevenue: kpi.totalRevenue,
        totalExpenditure: kpi.totalExpenditure,
        netIncome: kpi.netIncome,
        avgProfitMargin: kpi.avgProfitMargin,
        avgAccuracyScore: kpi.avgAccuracyScore,
        totalTransactions: kpi.totalTransactions,
        successRate,
      },
      charts: {
        revenueVsExpenditure,
        transactionsByAccountType,
        profitMarginDistribution,
        totalAmountByAccountType,
      },
    };
  }

  async getPlatformStatistics(range = '30d') {
    const daysToShow = range === '7d' ? 7 : 30;

    // Current Period
    const currentEnd = new Date();
    const currentStart = new Date();
    currentStart.setDate(currentStart.getDate() - daysToShow);
    currentStart.setHours(0, 0, 0, 0);

    // Previous Period (for growth calculation)
    const previousEnd = new Date(currentStart);
    const previousStart = new Date();
    previousStart.setDate(previousStart.getDate() - daysToShow * 2);
    previousStart.setHours(0, 0, 0, 0);

    // Helper to get counts for a period
    const getStatsForPeriod = async (start: Date, end: Date) => {
      const totalUsers = await this.userModel.countDocuments({
        createdAt: { $lte: end },
      });
      const newRegistrations = await this.userModel.countDocuments({
        createdAt: { $gte: start, $lte: end },
      });
      const businessOwners = await this.userModel.countDocuments({
        role: 'BUSINESS_OWNER',
        createdAt: { $lte: end },
      });
      const pendingApplications = await this.applicationModel.countDocuments({
        status: 'pending',
        createdAt: { $lte: end },
      });

      return {
        totalUsers,
        newRegistrations,
        businessOwners,
        pendingApplications,
      };
    };

    const currentStats = await getStatsForPeriod(currentStart, currentEnd);
    const previousStats = await getStatsForPeriod(previousStart, previousEnd);

    const growth = {
      totalUsers: calculateGrowth(
        currentStats.totalUsers,
        previousStats.totalUsers
      ),
      newRegistrations: calculateGrowth(
        currentStats.newRegistrations,
        previousStats.newRegistrations
      ),
      businessOwners: calculateGrowth(
        currentStats.businessOwners,
        previousStats.businessOwners
      ),
      pendingApplications: calculateGrowth(
        currentStats.pendingApplications,
        previousStats.pendingApplications
      ),
    };

    // Registration Trends (always 30 days for the chart to remain helpful as per previous request)
    const trendDays = 30;
    const trendStart = new Date();
    trendStart.setDate(trendStart.getDate() - trendDays);
    trendStart.setHours(0, 0, 0, 0);

    const registrationTrendsPipeline = [
      {
        $match: {
          createdAt: { $gte: trendStart },
        },
      },
      {
        $group: {
          _id: {
            day: { $dayOfMonth: '$createdAt' },
            month: { $month: '$createdAt' },
            year: { $year: '$createdAt' },
            fullDate: {
              $dateToString: { format: '%Y-%m-%d', date: '$createdAt' },
            },
          },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.fullDate': 1 as const } },
    ];

    const rawTrends = await this.userModel.aggregate<{
      _id: { fullDate: string };
      count: number;
    }>(registrationTrendsPipeline);

    const registrationTrends: {
      name: string;
      users: number;
      fullDate: string;
    }[] = [];
    for (let i = trendDays; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const entry = rawTrends.find((r) => r._id.fullDate === dateStr);

      registrationTrends.push({
        name: d.toLocaleDateString(undefined, {
          month: 'short',
          day: 'numeric',
        }),
        users: entry ? entry.count : 0,
        fullDate: dateStr,
      });
    }

    // Pie chart for users by role (current state)
    const usersByRolePipeline = [
      {
        $group: {
          _id: '$role',
          count: { $sum: 1 },
        },
      },
    ];

    const usersByRoleData = await this.userModel.aggregate<{
      _id: string;
      count: number;
    }>(usersByRolePipeline);
    const usersByRole = usersByRoleData.map((item) => ({
      name: item._id ?? 'UNKNOWN',
      value: item.count,
    }));

    return {
      kpis: currentStats,
      growth,
      charts: {
        registrationTrends,
        usersByRole,
      },
    };
  }

  async getExchangeRate(from: string, to: string): Promise<number> {
    if (from === to) return 1;
    // Hardcoded fallbacks for currencies not supported by Frankfurter (ECB)
    if (to === 'TND') return 3.12;

    try {
      const response = await fetch(
        `https://api.frankfurter.app/latest?from=${from}&to=${to}`
      );
      if (!response.ok) {
        const fallbacks: Record<string, number> = { EUR: 0.92, TND: 3.12 };
        return fallbacks[to] ?? 1;
      }
      const data = (await response.json()) as { rates: Record<string, number> };
      return data.rates[to] ?? 1;
    } catch (error) {
      console.error('Failed to fetch exchange rate:', error);
      const fallbacks: Record<string, number> = { EUR: 0.92, TND: 3.12 };
      return fallbacks[to] || 1;
    }
  }

  async getFilteredTransactions(
    query: TransactionQueryDto
  ): Promise<Record<string, unknown>[]> {
    const { startDate, endDate, type, limit = 50, offset = 0 } = query;
    const queryFilter: Record<string, unknown> = {};
    const conditions: Record<string, unknown>[] = [];

    if (startDate || endDate) {
      const dateCondition: Record<string, unknown> = {};
      if (startDate) dateCondition.$gte = new Date(startDate);
      if (endDate) dateCondition.$lte = new Date(endDate);
      conditions.push({
        $or: [{ Date: dateCondition }, { date: dateCondition }],
      });
    }

    if (type?.toString() === 'income') {
      conditions.push({
        $or: [{ Revenue: { $gt: 0 } }, { revenue: { $gt: 0 } }],
      });
    } else if (type?.toString() === 'expense') {
      conditions.push({
        $or: [{ Expenditure: { $gt: 0 } }, { expenditure: { $gt: 0 } }],
      });
    }

    if (conditions.length > 0) {
      queryFilter.$and = conditions;
    }

    const transactions = await this.transactionModel
      .find({ ...queryFilter })
      .select({
        Date: 1,
        date: 1,
        'Account Type': 1,
        accountType: 1,
        'Transaction Amount': 1,
        transactionAmount: 1,
        amount: 1,
        Revenue: 1,
        revenue: 1,
        Expenditure: 1,
        expenditure: 1,
        'Transaction ID': 1,
        transactionId: 1,
        originalCurrency: 1,
        convertedCurrency: 1,
        exchangeRate: 1,
        convertedAmount: 1,
      })
      .sort({ Date: -1 })
      .skip(offset)
      .limit(limit)
      .lean()
      .exec();

    return transactions.map((t) => {
      const raw = t as unknown as Record<string, unknown>;
      const originalAmount =
        Number(raw['Transaction Amount']) ||
        Number(raw.transactionAmount) ||
        Number(raw.amount) ||
        0;
      const convertedAmount = (raw.convertedAmount as number) ?? originalAmount;
      const originalCurrency = (raw.originalCurrency as string) ?? 'USD';
      const convertedCurrency = (raw.convertedCurrency as string) ?? 'USD';
      const exchangeRate = (raw.exchangeRate as number) ?? 1;

      const rev = Number(raw.Revenue) || Number(raw.revenue) || 0;
      const exp = Number(raw.Expenditure) || Number(raw.expenditure) || 0;

      return {
        id: (raw._id as { toString: () => string }).toString(),
        date: (raw.Date as string | Date) ?? (raw.date as string | Date),
        accountType:
          (raw['Account Type'] as string) ?? (raw.accountType as string),
        amount: originalAmount,
        originalAmount,
        convertedAmount,
        originalCurrency,
        convertedCurrency,
        exchangeRate,
        transactionId:
          (raw['Transaction ID'] as string) ?? (raw.transactionId as string),
        type: rev > 0 ? 'income' : 'expense',
        revenue: rev,
        expenditure: exp,
      };
    });
  }

  async generateTransactionPdf(id: string): Promise<Buffer> {
    const transaction = await this.transactionModel.findById(id).lean().exec();
    if (!transaction) throw new Error('Transaction not found');

    // Map transaction to template data
    const raw = transaction as unknown as Record<string, unknown>;
    const amount = Number(raw['Transaction Amount']) || 0;

    // Map transaction to template data
    const data = {
      companyName: 'Accountia Ltd',
      companyAddress: '123 Business Way, Tech City',
      companyEmail: 'billing@accountia.com',
      clientName: (raw.clientName as string) ?? 'Valued Client',
      clientAddress:
        (raw.clientAddress as string) ?? 'Client address placeholder',
      clientEmail: (raw.clientEmail as string) ?? 'client@example.com',
      invoiceNumber: `INV-${id.slice(-6).toUpperCase()}`,
      invoiceDate: new Date(raw.Date as string | Date).toLocaleDateString(),
      dueDate: new Date(raw.Date as string | Date).toLocaleDateString(),
      items: [
        {
          description: (raw['Account Type'] as string) ?? 'General Transaction',
          quantity: 1,
          price: amount,
          total: amount,
        },
      ],
      subtotal: amount,
      taxRate: 0,
      taxAmount: 0,
      totalAmount: amount,
    };

    return this.pdfService.generatePdf(data);
  }

  async getClientFinancials(clientId: string, _tenantDbName: string) {
    const pipeline = [
      {
        $match: {
          clientId: clientId, // Filtering transactions for this specific client
        },
      },
      {
        $group: {
          _id: undefined,
          totalRevenue: { $sum: '$Revenue' },
          totalExpenditure: { $sum: '$Expenditure' },
          netIncome: { $sum: '$Net Income' },
        },
      },
    ];

    const results = await this.transactionModel.aggregate<{
      totalRevenue: number;
      totalExpenditure: number;
      netIncome: number;
    }>(pipeline);
    const metrics = results[0] ?? {
      totalRevenue: 0,
      totalExpenditure: 0,
      netIncome: 0,
    };

    return {
      revenue: metrics.totalRevenue,
      expenses: metrics.totalExpenditure,
      netIncome: metrics.netIncome,
    };
  }

  async getClientCashFlow(clientId: string, _tenantDbName: string) {
    const pipeline = [
      {
        $match: {
          clientId: clientId,
        },
      },
      {
        $group: {
          _id: {
            month: { $month: { $toDate: '$Date' } },
            year: { $year: { $toDate: '$Date' } },
          },
          revenue: { $sum: '$Revenue' },
          expenses: { $sum: '$Expenditure' },
        },
      },
      {
        $sort: { '_id.year': 1 as const, '_id.month': 1 as const },
      },
    ];

    const results = await this.transactionModel.aggregate(pipeline);

    const monthNames = [
      'Jan',
      'Feb',
      'Mar',
      'Apr',
      'May',
      'Jun',
      'Jul',
      'Aug',
      'Sep',
      'Oct',
      'Nov',
      'Dec',
    ];

    const chartData = results.map((itemRaw) => {
      const item = itemRaw as {
        _id: { month: number; year: number };
        revenue: number;
        expenses: number;
      };
      return {
        name: `${monthNames[item._id.month - 1]} ${item._id.year}`,
        Revenue: item.revenue,
        Expenses: item.expenses,
      };
    });

    return chartData;
  }
}
