export interface AccountingJobResponse {
  taskId: string;
  status: string;
  message: string;
  estimatedCompletion?: string;
}

export interface AccountingJobStatus {
  taskId: string;
  businessId: string;
  periodStart: string;
  periodEnd: string;
  status: string;
  progressPercent: number;
  startedAt?: string;
  completedAt?: string;
  errorMessage?: string;
  journalEntriesCount: number;
  reportsGenerated: number;
}

export interface AccountingResults {
  taskId: string;
  businessId: string;
  periodStart: string;
  periodEnd: string;
  status: string;
  totalRevenue: number;
  totalExpenses: number;
  grossProfit: number;
  netProfit: number;
  accountsReceivable: number;
  accountsPayable: number;
  cashPosition: number;
  taxCalculations: TaxCalculation[];
  aiInsights: string;
  recommendations: string[];
  anomaliesDetected: Anomaly[];
  reports: Report[];
  journalEntriesPreview: JournalEntry[];
  totalJournalEntries: number;
}

export interface TaxCalculation {
  taxType: string;
  jurisdiction: string;
  taxableAmount: number;
  taxRate: number;
  taxAmount: number;
  notes?: string;
}

export interface Anomaly {
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
}

export interface Report {
  reportType: string;
  periodStart: string;
  periodEnd: string;
  data: Record<string, unknown>;
}

export interface JournalEntry {
  date: string;
  account: string;
  debit: number;
  credit: number;
  description: string;
}

export interface AccountingJobSummary {
  taskId: string;
  periodStart: string;
  periodEnd: string;
  status: string;
  completedAt?: string;
}

export interface BusinessJobsResponse {
  jobs: AccountingJobStatus[];
  total: number;
}

export interface FinancialSummary {
  totalRevenue: number;
  totalExpenses: number;
  grossProfit: number;
  netProfit: number;
  accountsReceivable: number;
  accountsPayable: number;
  cashPosition: number;
}

export interface AccountingPeriodDetail {
  taskId: string;
  periodStart: string;
  periodEnd: string;
  status: string;
  createdAt?: string;
  startedAt?: string;
  completedAt?: string;
  journalEntriesCount: number;
  taxCalculationsCount: number;
  reportsCount: number;
  hasAiInsights: boolean;
  recommendationsCount: number;
  financialSummary: FinancialSummary;
}

export interface BusinessWorkResponse {
  businessId: string;
  databaseName: string;
  summary: {
    totalAccountingPeriods: number;
    completed: number;
    pending: number;
    processing: number;
    failed: number;
    totalJournalEntriesGenerated: number;
    totalRevenueProcessed: number;
  };
  accountingPeriods: AccountingPeriodDetail[];
}

export interface MonthlyTaxDetail {
  month: number;
  period: string;
  vatStandard19: number;
  vatReduced13: number;
  vatReduced7: number;
  vatTotal: number;
  taxableIncome: number;
  corporateTaxDue: number;
  withholdingTax: number;
  totalTaxLiability: number;
  dueDate: string;
}

export interface TaxDeadline {
  period: string;
  dueDate: string;
  description: string;
}

export interface TaxSummaryResponse {
  businessId: string;
  businessName: string;
  year: number;
  currency: string;
  summary: {
    annualVatTotal: number;
    annualCorporateTax: number;
    annualWithholdingTax: number;
    totalTaxLiability: number;
  };
  vatBreakdown: {
    standardRate19Percent: number;
    reducedRate13Percent: number;
    reducedRate7Percent: number;
  };
  monthlyDetails: MonthlyTaxDetail[];
  taxCalendar: TaxDeadline[];
  notes: string[];
}
