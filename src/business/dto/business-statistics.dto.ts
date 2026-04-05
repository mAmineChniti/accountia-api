import { ApiProperty } from '@nestjs/swagger';

export class ProductStatisticsDto {
  @ApiProperty({ example: 12 })
  totalProducts!: number;

  @ApiProperty({ example: 4500.75 })
  totalValue!: number;

  @ApiProperty({ example: 3 })
  lowStockProducts!: number;
}

export class InvoiceStatisticsDto {
  @ApiProperty({ example: 25 })
  totalInvoices!: number;

  @ApiProperty({ example: 12_000.5 })
  paidAmount!: number;

  @ApiProperty({ example: 2500 })
  pendingAmount!: number;

  @ApiProperty({ example: 800 })
  overdueAmount!: number;

  @ApiProperty({ example: 18 })
  paidInvoices!: number;

  @ApiProperty({ example: 5 })
  pendingInvoices!: number;

  @ApiProperty({ example: 2 })
  overdueInvoices!: number;
}

export class BusinessStatisticsResponseDto {
  @ApiProperty({ example: '507f1f77bcf86cd799439011' })
  businessId!: string;

  @ApiProperty({ example: 'Evenix' })
  businessName!: string;

  @ApiProperty({ type: () => ProductStatisticsDto })
  products!: ProductStatisticsDto;

  @ApiProperty({ type: () => InvoiceStatisticsDto })
  invoices!: InvoiceStatisticsDto;

  @ApiProperty({ type: String, format: 'date-time' })
  lastUpdated!: Date;
}
