/**
 * Minimal interfaces for AI Accountant responses — shaped from sample payloads.
 * Keep these compact and only include fields we actually use.
 */

export interface CreateJobResponse {
  businessId: string;
  estimatedSeconds: number;
  message: string;
  status: string;
  taskId: string;
}

export interface JobSummary {
  taskId: string;
  status: string;
  journalEntriesCount: number;
  reportsGenerated: number;
  progressPercent: number;
  periodStart: string;
  periodEnd: string;
  completedAt: string;
}

export interface JobsListResponse {
  businessId: string;
  jobs: JobSummary[];
}

export interface JournalEntry {
  account: string;
  credit: number;
  date: string;
  debit: number;
  description: string;
  invoiceId: string;
}

export interface Report {
  reportType: string;
  data: {
    gross_profit: number;
    revenue: number;
  };
}

export interface TaxCalculation {
  taxType: string;
  jurisdiction: string;
  taxableAmount: number;
  taxRate: number;
  taxAmount: number;
  notes: string;
}

export interface AccountingResults {
  taskId: string;
  businessId: string;
  status: string;
  periodStart: string;
  periodEnd: string;
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
  anomaliesDetected: Array<{
    detail: string;
    relatedInvoiceId?: string;
    severity: 'low' | 'medium' | 'high';
    type: string;
  }>;
  reports: Report[];
  journalEntries: JournalEntry[];
  totalJournalEntries: number;
}

export interface TaxPersistResponse {
  businessId: string;
  success: boolean;
  year: number;
}

export interface TaxBreakdown {
  corporate_tax_due: number;
  corporate_tax_rate: number;
  due_date: string;
  filing_period: string;
  taxable_income: number;
  total_tax_liability: number;
  vat_exempt: number;
  vat_reduced_13: number;
  vat_reduced_7: number;
  vat_standard_19: number;
  vat_total: number;
  withholding_tax: number;
}

export interface TaxResultsResponse {
  businessId: string;
  year: number;
  analysis: Record<string, unknown>;
  llmRecommendations: string[];
  llmSummary: string;
  createdAt: string;
  lastUpdatedAt: string;
  taxBreakdown: TaxBreakdown;
}

export interface ServiceHealthChecks {
  model: boolean;
  mongodb: boolean;
  redis: boolean;
}

export interface ServiceModelInfo {
  modelPath: boolean | string;
  name: string;
  ready: boolean;
  usingTensorflow: boolean;
}

export interface ServiceHealthResponse {
  checks: ServiceHealthChecks;
  modelInfo: ServiceModelInfo;
  service: string;
  status: string;
  timestamp: string;
  version: string;
  workerPid: number;
}
