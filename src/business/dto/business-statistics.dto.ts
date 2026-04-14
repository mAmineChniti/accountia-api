import { ApiProperty } from '@nestjs/swagger';

// ─── Client Podium (unchanged) ────────────────────────────────────────────────

export class ClientPodiumEntryDto {
  @ApiProperty({ example: '507f1f77bcf86cd799439011' })
  clientId!: string;

  @ApiProperty({ example: 'John Doe' })
  clientName!: string;

  @ApiProperty({ example: 'john@example.com' })
  clientEmail!: string;

  @ApiProperty({ example: 15_000.5 })
  totalPaidAmount!: number;

  @ApiProperty({ example: 12 })
  totalPaidInvoices!: number;

  @ApiProperty({ example: '🥇' })
  medal!: string;
}

export class ClientPodiumDto {
  @ApiProperty({ type: [ClientPodiumEntryDto], isArray: true })
  podium!: ClientPodiumEntryDto[];
}

// ─── Time-Series Primitives ───────────────────────────────────────────────────

export class MonthlyDataPointDto {
  @ApiProperty({ example: '2024-01', description: 'ISO month (YYYY-MM)' })
  date!: string;

  @ApiProperty({ example: 12_500 })
  value!: number;
}

export class TimeSeriesDataDto {
  @ApiProperty({
    type: [MonthlyDataPointDto],
    isArray: true,
    description: 'Real observed business data',
  })
  historical!: MonthlyDataPointDto[];

  @ApiProperty({
    type: [MonthlyDataPointDto],
    isArray: true,
    description: 'TensorFlow forecast (future only)',
  })
  predicted!: MonthlyDataPointDto[];
}

// ─── Financial KPIs ───────────────────────────────────────────────────────────

export class FinancialKpisDto {
  @ApiProperty({
    example: 125_000,
    description: 'Total revenue (accrual basis)',
  })
  totalRevenue!: number;

  @ApiProperty({ example: 75_000, description: 'Cost of Goods Sold' })
  totalCOGS!: number;

  @ApiProperty({ example: 50_000, description: 'Revenue − COGS' })
  grossProfit!: number;

  @ApiProperty({
    example: 50_000,
    description: 'Gross profit (no separate OpEx data available)',
  })
  netProfit!: number;

  @ApiProperty({ example: 40, description: '(GrossProfit / Revenue) × 100' })
  profitMarginPercent!: number;

  @ApiProperty({
    example: 12.5,
    description: 'Revenue growth vs previous comparable period (%)',
  })
  revenueGrowthRatePercent!: number | undefined;
}

// ─── Revenue Time-Series (chart-ready) ─────────────────────────────────────────

export class RevenueTimeSeriesDto {
  @ApiProperty({ type: TimeSeriesDataDto })
  revenue!: TimeSeriesDataDto;

  @ApiProperty({ type: TimeSeriesDataDto })
  cogs!: TimeSeriesDataDto;

  @ApiProperty({ type: TimeSeriesDataDto })
  grossProfit!: TimeSeriesDataDto;

  @ApiProperty({ type: TimeSeriesDataDto, description: 'Units sold over time' })
  salesVolume!: TimeSeriesDataDto;
}

// ─── Invoice Statistics ────────────────────────────────────────────────────────

export class InvoiceStatisticsDto {
  @ApiProperty({ example: 25 })
  totalInvoices!: number;

  @ApiProperty({ example: 18 })
  paidInvoices!: number;

  @ApiProperty({ example: 5 })
  pendingInvoices!: number;

  @ApiProperty({ example: 2 })
  overdueInvoices!: number;

  @ApiProperty({ example: 12_000.5 })
  paidAmount!: number;

  @ApiProperty({ example: 2500 })
  pendingAmount!: number;

  @ApiProperty({ example: 800 })
  overdueAmount!: number;
}

// ─── Product Statistics ────────────────────────────────────────────────────────

export class ProductStatisticsDto {
  @ApiProperty({ example: 12 })
  totalProducts!: number;

  @ApiProperty({
    example: 4500.75,
    description: 'Sum of (unitPrice × quantity) across all products',
  })
  totalInventoryValue!: number;

  @ApiProperty({ example: 3, description: 'Products with quantity ≤ 5' })
  lowStockProducts!: number;
}

// ─── Product Profitability ─────────────────────────────────────────────────────

export class ProductProfitabilityDto {
  @ApiProperty({ example: '507f1f77bcf86cd799439099' })
  productId!: string;

  @ApiProperty({ example: 'HP EliteBook' })
  productName!: string;

  @ApiProperty({ example: 1500 })
  unitPrice!: number;

  @ApiProperty({ example: 900 })
  unitCost!: number;

  @ApiProperty({ example: 8 })
  soldQuantity!: number;

  @ApiProperty({ example: 12_000 })
  revenue!: number;

  @ApiProperty({ example: 7200 })
  totalCost!: number;

  @ApiProperty({ example: 4800 })
  grossProfit!: number;

  @ApiProperty({ example: 40 })
  profitMarginPercent!: number;
}

// ─── Sales Analytics ──────────────────────────────────────────────────────────

export class SalesAnalyticsDto {
  @ApiProperty({ type: TimeSeriesDataDto, description: 'Units sold per month' })
  salesVolume!: TimeSeriesDataDto;

  @ApiProperty({
    type: [ProductProfitabilityDto],
    isArray: true,
    description: 'Top 5 products by revenue',
  })
  topProducts!: ProductProfitabilityDto[];

  @ApiProperty({
    type: [ProductProfitabilityDto],
    isArray: true,
    description: 'Bottom 5 products by profit margin',
  })
  underperformingProducts!: ProductProfitabilityDto[];

  @ApiProperty({ example: 'growth', enum: ['growth', 'decline', 'stagnation'] })
  salesTrend!: 'growth' | 'decline' | 'stagnation';
}

// ─── Main Response ─────────────────────────────────────────────────────────────

export class BusinessStatisticsResponseDto {
  @ApiProperty({ example: 'Business statistics retrieved successfully' })
  message!: string;

  @ApiProperty({ example: '507f1f77bcf86cd799439011' })
  businessId!: string;

  @ApiProperty({
    example: { start: '2023-01', end: '2024-12' },
    description: 'Date range of historical data',
  })
  period!: { start: string; end: string };

  @ApiProperty({ type: FinancialKpisDto })
  kpis!: FinancialKpisDto;

  @ApiProperty({ type: RevenueTimeSeriesDto })
  revenueTimeSeries!: RevenueTimeSeriesDto;

  @ApiProperty({ type: InvoiceStatisticsDto })
  invoiceStatistics!: InvoiceStatisticsDto;

  @ApiProperty({ type: ProductStatisticsDto })
  productStatistics!: ProductStatisticsDto;

  @ApiProperty({ type: SalesAnalyticsDto })
  salesAnalytics!: SalesAnalyticsDto;
}
