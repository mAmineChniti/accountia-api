export interface AccountingJobResponse {
  task_id: string;
  status: string;
  message: string;
  estimated_completion?: string;
}

export interface AccountingJobStatus {
  task_id: string;
  business_id: string;
  period_start: string;
  period_end: string;
  status: string;
  progress_percent: number;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  journal_entries_count: number;
  reports_generated: number;
}

export interface AccountingResults {
  task_id: string;
  business_id: string;
  period_start: string;
  period_end: string;
  status: string;
  total_revenue: number;
  total_expenses: number;
  gross_profit: number;
  net_profit: number;
  accounts_receivable: number;
  accounts_payable: number;
  cash_position: number;
  tax_calculations: TaxCalculation[];
  ai_insights: string;
  recommendations: string[];
  anomalies_detected: Anomaly[];
  reports: Report[];
  journal_entries_preview: JournalEntry[];
  total_journal_entries: number;
}

export interface TaxCalculation {
  tax_type: string;
  jurisdiction: string;
  taxable_amount: number;
  tax_rate: number;
  tax_amount: number;
  notes?: string;
}

export interface Anomaly {
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
}

export interface Report {
  report_type: string;
  period_start: string;
  period_end: string;
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
  task_id: string;
  period_start: string;
  period_end: string;
  status: string;
  completed_at?: string;
}

export interface BusinessJobsResponse {
  jobs: AccountingJobStatus[];
  total: number;
}

export interface FinancialSummary {
  total_revenue: number;
  total_expenses: number;
  gross_profit: number;
  net_profit: number;
  accounts_receivable: number;
  accounts_payable: number;
  cash_position: number;
}

export interface AccountingPeriodDetail {
  task_id: string;
  period_start: string;
  period_end: string;
  status: string;
  created_at?: string;
  started_at?: string;
  completed_at?: string;
  journal_entries_count: number;
  tax_calculations_count: number;
  reports_count: number;
  has_ai_insights: boolean;
  recommendations_count: number;
  financial_summary: FinancialSummary;
}

export interface BusinessWorkResponse {
  business_id: string;
  database_name: string;
  summary: {
    total_accounting_periods: number;
    completed: number;
    pending: number;
    processing: number;
    failed: number;
    total_journal_entries_generated: number;
    total_revenue_processed: number;
  };
  accounting_periods: AccountingPeriodDetail[];
}

export interface MonthlyTaxDetail {
  month: number;
  period: string;
  vat_standard_19: number;
  vat_reduced_13: number;
  vat_reduced_7: number;
  vat_total: number;
  taxable_income: number;
  corporate_tax_due: number;
  withholding_tax: number;
  total_tax_liability: number;
  due_date: string;
}

export interface TaxDeadline {
  period: string;
  due_date: string;
  description: string;
}

export interface TaxSummaryResponse {
  business_id: string;
  business_name: string;
  year: number;
  currency: string;
  summary: {
    annual_vat_total: number;
    annual_corporate_tax: number;
    annual_withholding_tax: number;
    total_tax_liability: number;
  };
  vat_breakdown: {
    standard_rate_19_percent: number;
    reduced_rate_13_percent: number;
    reduced_rate_7_percent: number;
  };
  monthly_details: MonthlyTaxDetail[];
  tax_calendar: TaxDeadline[];
  notes: string[];
}
