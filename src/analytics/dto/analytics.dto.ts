import { IsString, IsOptional } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class AnalyticsQueryDto {
  @IsString()
  businessId!: string;

  @ApiPropertyOptional({ description: 'Start date ISO 8601' })
  @IsOptional()
  @IsString()
  startDate?: string;

  @ApiPropertyOptional({ description: 'End date ISO 8601' })
  @IsOptional()
  @IsString()
  endDate?: string;

  @ApiPropertyOptional({
    default: 'monthly',
    enum: ['monthly', 'weekly', 'yearly'],
  })
  @IsOptional()
  @IsString()
  groupBy?: string;
}

export class RevenueDataPointDto {
  period!: string;
  revenue!: number;
  invoiceCount!: number;
  paid!: number;
  unpaid!: number;
}

export class AgingBucketDto {
  label!: string;
  amount!: number;
  count!: number;
  daysRange!: string;
}

export class TopClientDto {
  clientName!: string;
  totalRevenue!: number;
  invoiceCount!: number;
  avgDaysToPay!: number;
  lastInvoiceDate!: string;
}

export class CashFlowForecastDto {
  date!: string;
  expectedInflow!: number;
  invoiceNumber!: string;
  recipientName!: string;
  status!: string;
}

export class FinancialSummaryDto {
  totalRevenue!: number;
  totalOutstanding!: number;
  totalOverdue!: number;
  totalPaid!: number;
  averageInvoiceValue!: number;
  collectionRate!: number;
  averageDaysToPay!: number;
  currency!: string;
}

export class AnalyticsDashboardDto {
  summary!: FinancialSummaryDto;
  revenueTimeline!: RevenueDataPointDto[];
  arAging!: AgingBucketDto[];
  topClients!: TopClientDto[];
  cashFlowForecast!: CashFlowForecastDto[];
  expenseSummary?: {
    total: number;
    byCategory: Array<{ category: string; total: number }>;
  };
}
