import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export type StockRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export class StockInsightItemDto {
  @ApiProperty()
  productId!: string;

  @ApiProperty()
  productName!: string;

  @ApiProperty()
  currentQuantity!: number;

  @ApiProperty()
  soldLastPeriod!: number;

  @ApiProperty()
  dailySalesRate!: number;

  @ApiPropertyOptional({
    description: 'Estimated days until stockout, or undefined if no sales data',
  })
  estimatedDaysUntilStockout?: number;

  @ApiProperty({ enum: ['LOW', 'MEDIUM', 'HIGH'] })
  riskLevel!: StockRiskLevel;

  @ApiProperty()
  safetyStock!: number;

  @ApiProperty()
  recommendedReorderQuantity!: number;

  @ApiProperty()
  reason!: string;

  @ApiProperty()
  recommendation!: string;
}

export class StockInsightsSummaryDto {
  @ApiProperty()
  totalProducts!: number;

  @ApiProperty()
  highRiskCount!: number;

  @ApiProperty()
  mediumRiskCount!: number;

  @ApiProperty()
  lowRiskCount!: number;

  @ApiProperty()
  totalRecommendedUnits!: number;
}

export class StockInsightsResponseDto {
  @ApiProperty()
  businessId!: string;

  @ApiProperty()
  generatedAt!: Date;

  @ApiProperty()
  lookbackDays!: number;

  @ApiProperty()
  planningHorizonDays!: number;

  @ApiProperty({ type: StockInsightsSummaryDto })
  summary!: StockInsightsSummaryDto;

  @ApiProperty({ type: [StockInsightItemDto], isArray: true })
  items!: StockInsightItemDto[];
}
