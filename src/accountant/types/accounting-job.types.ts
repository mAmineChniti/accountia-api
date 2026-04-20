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
