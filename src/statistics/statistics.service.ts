import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Transaction, TransactionDocument } from './schemas/transaction.schema';
import { User, UserDocument } from '@/users/schemas/user.schema';
import { BusinessApplication, BusinessApplicationDocument } from '@/business/schemas/business-application.schema';
import { AuditLog, AuditLogDocument } from './schemas/audit-log.schema';
import { OnModuleInit } from '@nestjs/common';
import { TransactionQueryDto, TransactionType } from './dto/transaction-query.dto';
import { InvoicePdfService } from './invoice-pdf.service';

@Injectable()
export class StatisticsService implements OnModuleInit {
  constructor(
    @InjectModel(Transaction.name) private transactionModel: Model<TransactionDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(BusinessApplication.name) private applicationModel: Model<BusinessApplicationDocument>,
    @InjectModel(AuditLog.name) private auditLogModel: Model<AuditLogDocument>,
    private readonly pdfService: InvoicePdfService,
  ) { }

  async onModuleInit() {
    try {
      // Seed initial logs if none exist for demonstration
      const count = await Promise.race([
        this.auditLogModel.countDocuments(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('DB Timeout')), 5000))
      ]);

      if (count === 0) {
        const demoLogs = [
          { userId: 'system', username: 'System', action: 'CREATE', resource: 'User', details: { message: 'Admin dashboard initialized' }, createdAt: new Date() },
          { userId: 'admin', username: 'Admin', action: 'UPDATE', resource: 'Settings', details: { message: 'Platform constraints updated' }, createdAt: new Date(Date.now() - 1000 * 60 * 5) },
          { userId: 'admin', username: 'Admin', action: 'DELETE', resource: 'User', details: { message: 'Test account removed' }, createdAt: new Date(Date.now() - 1000 * 60 * 15) },
        ];
        await this.auditLogModel.insertMany(demoLogs);
      }
    } catch (error) {
      console.warn('Audit logs seeding skipped or timed out:', (error as Error).message);
    }
  }

  async createLog(userId: string, username: string, action: string, resource: string, details?: any) {
    const log = new this.auditLogModel({
      userId,
      username,
      action,
      resource,
      details,
    });
    return log.save();
  }

  async getAuditLogs(limit: number = 20) {
    return this.auditLogModel.find().sort({ createdAt: -1 }).limit(limit).exec();
  }

  async getStatistics() {
    const kpisPipeline = [
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: '$Revenue' },
          totalExpenditure: { $sum: '$Expenditure' },
          netIncome: { $sum: '$Net Income' },
          avgProfitMargin: { $avg: '$Profit Margin' },
          avgAccuracyScore: { $avg: '$Accuracy Score' },
          totalTransactions: { $sum: 1 },
          successCount: {
            $sum: { $cond: [{ $eq: ['$Transaction Outcome', 1] }, 1, 0] }
          }
        }
      }
    ];

    const kpiResults = await this.transactionModel.aggregate(kpisPipeline);
    const kpi = kpiResults[0] || {
      totalRevenue: 0,
      totalExpenditure: 0,
      netIncome: 0,
      avgProfitMargin: 0,
      avgAccuracyScore: 0,
      totalTransactions: 0,
      successCount: 0,
    };

    const successRate = kpi.totalTransactions > 0
      ? (kpi.successCount / kpi.totalTransactions) * 100
      : 0;

    const timeSeriesPipeline = [
      {
        $group: {
          _id: {
            month: { $month: { $toDate: "$Date" } },
            year: { $year: { $toDate: "$Date" } }
          },
          revenue: { $sum: '$Revenue' },
          expenditure: { $sum: '$Expenditure' },
          netIncome: { $sum: '$Net Income' }
        }
      },
      { $sort: { "_id.year": 1 as 1, "_id.month": 1 as 1 } }
    ];

    const timeSeriesData = await this.transactionModel.aggregate(timeSeriesPipeline);
    const revenueVsExpenditure = timeSeriesData.map(item => ({
      name: `${item._id.month}/${item._id.year}`,
      Revenue: item.revenue,
      Expenditure: item.expenditure,
      "Net Income": item.netIncome
    }));

    const accountTypePipeline = [
      {
        $group: {
          _id: '$Account Type',
          count: { $sum: 1 },
          amount: { $sum: '$Transaction Amount' }
        }
      }
    ];
    const accountTypeData = await this.transactionModel.aggregate(accountTypePipeline);

    const transactionsByAccountType = accountTypeData.map(item => ({
      name: item._id || 'Unknown',
      value: item.count
    }));

    const totalAmountByAccountType = accountTypeData.map(item => ({
      name: item._id || 'Unknown',
      value: item.amount
    }));

    const marginDistributionPipeline = [
      {
        $bucket: {
          groupBy: "$Profit Margin",
          boundaries: [0, 0.25, 0.5, 0.75, 1],
          default: "Other",
          output: { count: { $sum: 1 } }
        }
      }
    ];

    // Fallback if there are no documents matching the bucket
    let marginData: any[] = [];
    try {
      marginData = await this.transactionModel.aggregate(marginDistributionPipeline);
    } catch (e) {
      // Bucket can fail if no data
      marginData = [];
    }

    const profitMarginDistribution = marginData.map(item => {
      let label = "Other";
      if (item._id === 0) label = "0-25%";
      else if (item._id === 0.25) label = "25-50%";
      else if (item._id === 0.5) label = "50-75%";
      else if (item._id === 0.75) label = "75-100%";
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
        successRate
      },
      charts: {
        revenueVsExpenditure,
        transactionsByAccountType,
        profitMarginDistribution,
        totalAmountByAccountType
      }
    };
  }

  async getPlatformStatistics(range: string = '30d') {
    const daysToShow = range === '7d' ? 7 : 30;

    // Current Period
    const currentEnd = new Date();
    const currentStart = new Date();
    currentStart.setDate(currentStart.getDate() - daysToShow);
    currentStart.setHours(0, 0, 0, 0);

    // Previous Period (for growth calculation)
    const previousEnd = new Date(currentStart);
    const previousStart = new Date();
    previousStart.setDate(previousStart.getDate() - (daysToShow * 2));
    previousStart.setHours(0, 0, 0, 0);

    // Helper to get counts for a period
    const getStatsForPeriod = async (start: Date, end: Date) => {
      const totalUsers = await this.userModel.countDocuments({ createdAt: { $lte: end } });
      const newRegistrations = await this.userModel.countDocuments({ createdAt: { $gte: start, $lte: end } });
      const businessOwners = await this.userModel.countDocuments({ role: 'BUSINESS_OWNER', createdAt: { $lte: end } });
      const pendingApplications = await this.applicationModel.countDocuments({ status: 'pending', createdAt: { $lte: end } });

      return { totalUsers, newRegistrations, businessOwners, pendingApplications };
    };

    const currentStats = await getStatsForPeriod(currentStart, currentEnd);
    const previousStats = await getStatsForPeriod(previousStart, previousEnd);

    // Calculate Growth Percentage
    const calculateGrowth = (current: number, previous: number) => {
      if (previous === 0) return current > 0 ? 100 : 0;
      return parseFloat(((current - previous) / previous * 100).toFixed(1));
    };

    const growth = {
      totalUsers: calculateGrowth(currentStats.totalUsers, previousStats.totalUsers),
      newRegistrations: calculateGrowth(currentStats.newRegistrations, previousStats.newRegistrations),
      businessOwners: calculateGrowth(currentStats.businessOwners, previousStats.businessOwners),
      pendingApplications: calculateGrowth(currentStats.pendingApplications, previousStats.pendingApplications),
    };

    // Registration Trends (always 30 days for the chart to remain helpful as per previous request)
    const trendDays = 30;
    const trendStart = new Date();
    trendStart.setDate(trendStart.getDate() - trendDays);
    trendStart.setHours(0, 0, 0, 0);

    const registrationTrendsPipeline = [
      {
        $match: {
          createdAt: { $gte: trendStart }
        }
      },
      {
        $group: {
          _id: {
            day: { $dayOfMonth: "$createdAt" },
            month: { $month: "$createdAt" },
            year: { $year: "$createdAt" },
            fullDate: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id.fullDate": 1 as 1 } }
    ];

    const rawTrends = await this.userModel.aggregate(registrationTrendsPipeline);

    const registrationTrends: any[] = [];
    for (let i = trendDays; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const entry = rawTrends.find((r: any) => r._id.fullDate === dateStr);

      registrationTrends.push({
        name: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
        users: entry ? entry.count : 0,
        fullDate: dateStr
      });
    }

    // Pie chart for users by role (current state)
    const usersByRolePipeline = [
      {
        $group: {
          _id: "$role",
          count: { $sum: 1 }
        }
      }
    ];

    const usersByRoleData = await this.userModel.aggregate(usersByRolePipeline);
    const usersByRole = usersByRoleData.map((item: any) => ({
      name: item._id || 'UNKNOWN',
      value: item.count
    }));

    return {
      kpis: currentStats,
      growth,
      charts: {
        registrationTrends,
        usersByRole
      }
    };
  }

  async getExchangeRate(from: string, to: string): Promise<number> {
    if (from === to) return 1;
    // Hardcoded fallbacks for currencies not supported by Frankfurter (ECB)
    if (to === 'TND') return 3.12;

    try {
      const response = await fetch(`https://api.frankfurter.app/latest?from=${from}&to=${to}`);
      if (!response.ok) {
        const fallbacks: Record<string, number> = { EUR: 0.92, TND: 3.12 };
        return fallbacks[to] || 1;
      }
      const data = (await response.json()) as any;
      return data.rates[to] || 1;
    } catch (error) {
      console.error('Failed to fetch exchange rate:', error);
      const fallbacks: Record<string, number> = { EUR: 0.92, TND: 3.12 };
      return fallbacks[to] || 1;
    }
  }

  async getFilteredTransactions(query: TransactionQueryDto): Promise<any[]> {
    const { startDate, endDate, type, limit = 50, offset = 0 } = query;
    const filter: any = {};

    if (startDate || endDate) {
      filter.Date = {};
      if (startDate) filter.Date.$gte = new Date(startDate);
      if (endDate) filter.Date.$lte = new Date(endDate);
    }

    if (type === TransactionType.INCOME) {
      filter.Revenue = { $gt: 0 };
    } else if (type === TransactionType.EXPENSE) {
      filter.Expenditure = { $gt: 0 };
    }

    const transactions = await this.transactionModel
      .find(filter)
      .select({
        'Date': 1,
        'Account Type': 1,
        'Transaction Amount': 1,
        'Revenue': 1,
        'Expenditure': 1,
        'Transaction ID': 1,
        'originalCurrency': 1,
        'convertedCurrency': 1,
        'exchangeRate': 1,
        'convertedAmount': 1
      })
      .sort({ Date: -1 })
      .skip(offset)
      .limit(limit)
      .lean()
      .exec();

    return transactions.map((t: any) => {
      const originalAmount = Number(t['Transaction Amount']) || 0;
      const convertedAmount = t.convertedAmount ?? originalAmount;
      const originalCurrency = t.originalCurrency || 'USD';
      const convertedCurrency = t.convertedCurrency || 'USD';
      const exchangeRate = t.exchangeRate || 1;

      return {
        id: t._id.toString(),
        date: t['Date'],
        accountType: t['Account Type'],
        amount: originalAmount,
        originalAmount,
        convertedAmount,
        originalCurrency,
        convertedCurrency,
        exchangeRate,
        transactionId: t['Transaction ID'],
        type: t['Revenue'] > 0 ? 'income' : 'expense',
        revenue: t['Revenue'],
        expenditure: t['Expenditure'],
      };
    });
  }

  async generateTransactionPdf(id: string): Promise<Buffer> {
    const transaction = await this.transactionModel.findById(id).lean().exec();
    if (!transaction) throw new Error('Transaction not found');

    const amount = Number(transaction['Transaction Amount']) || 0;

    // Map transaction to template data
    const data = {
      companyName: 'Accountia Ltd',
      companyAddress: '123 Business Way, Tech City',
      companyEmail: 'billing@accountia.com',
      clientName: (transaction as any).clientName || 'Valued Client',
      clientAddress: (transaction as any).clientAddress || 'Client address placeholder',
      clientEmail: (transaction as any).clientEmail || 'client@example.com',
      invoiceNumber: `INV-${id.slice(-6).toUpperCase()}`,
      invoiceDate: new Date(transaction['Date']).toLocaleDateString(),
      dueDate: new Date(transaction['Date']).toLocaleDateString(),
      items: [
        {
          description: transaction['Account Type'] || 'General Transaction',
          quantity: 1,
          price: amount,
          total: amount
        }
      ],
      subtotal: amount,
      taxRate: 0,
      taxAmount: 0,
      totalAmount: amount
    };

    return this.pdfService.generatePdf(data);
  }

  async getClientFinancials(clientId: string, tenantDbName: string) {
    const pipeline = [
      {
        $match: {
          clientId: clientId, // Filtering transactions for this specific client
        }
      },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: '$Revenue' },
          totalExpenditure: { $sum: '$Expenditure' },
          netIncome: { $sum: '$Net Income' },
        }
      }
    ];

    const results = await this.transactionModel.aggregate(pipeline);
    const metrics = results[0] || {
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

  async getClientCashFlow(clientId: string, tenantDbName: string) {
    const pipeline = [
      {
        $match: {
          clientId: clientId,
        }
      },
      {
        $group: {
          _id: {
            month: { $month: { $toDate: "$Date" } },
            year: { $year: { $toDate: "$Date" } }
          },
          revenue: { $sum: '$Revenue' },
          expenses: { $sum: '$Expenditure' }
        }
      },
      {
        $sort: { "_id.year": 1 as 1, "_id.month": 1 as 1 }
      }
    ];

    const results = await this.transactionModel.aggregate(pipeline);

    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    const chartData = results.map((item: any) => ({
      name: `${monthNames[item._id.month - 1]} ${item._id.year}`,
      Revenue: item.revenue,
      Expenses: item.expenses
    }));

    return chartData;
  }
}

