export class ProductStatisticsDto {
  totalProducts!: number;
  totalValue!: number;
  lowStockProducts!: number;
}

export class InvoiceStatisticsDto {
  totalInvoices!: number;
  paidAmount!: number;
  pendingAmount!: number;
  overdueAmount!: number;
  paidInvoices!: number;
  pendingInvoices!: number;
  overdueInvoices!: number;
}

export class BusinessStatisticsResponseDto {
  businessId!: string;
  businessName!: string;
  products!: ProductStatisticsDto;
  invoices!: InvoiceStatisticsDto;
  lastUpdated!: Date;
}
