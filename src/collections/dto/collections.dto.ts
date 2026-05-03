import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

// ─── Risk level classifications──────────────────────────────────────────────

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// ─── Per-invoice risk score ──────────────────────────────────────────────────

export class InvoiceRiskScoreDto {
  @ApiProperty({ description: 'Invoice ID' })
  invoiceId!: string;

  @ApiProperty({ description: 'Invoice number for display' })
  invoiceNumber!: string;

  @ApiProperty({ description: 'Total invoice amount' })
  totalAmount!: number;

  @ApiProperty({ description: 'Amount still outstanding' })
  outstandingAmount!: number;

  @ApiProperty({ description: 'Currency code' })
  currency!: string;

  @ApiProperty({ description: 'Due date (ISO string)' })
  dueDate!: string;

  @ApiProperty({ description: 'How many days past due (0 if not yet due)' })
  daysOverdue!: number;

  @ApiProperty({ description: 'Current invoice status' })
  status!: string;

  @ApiProperty({ description: 'Recipient display name or email' })
  recipientLabel!: string;

  @ApiProperty({
    description: 'Risk score 0–100 (higher = more likely to default)',
  })
  riskScore!: number;

  @ApiProperty({
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    description: 'Risk level classification',
  })
  riskLevel!: RiskLevel;

  @ApiProperty({
    description: 'Number of past invoices used to build this score',
  })
  historyCount!: number;

  @ApiPropertyOptional({
    description: 'Average days the client historically takes to pay',
  })
  avgHistoricalDelayDays?: number;

  @ApiPropertyOptional({
    description:
      'Client late-payment rate 0–1 (e.g. 0.4 = 40% of past invoices were late)',
  })
  clientLatePaymentRate?: number;
}

// ─── Collections dashboard aggregate ────────────────────────────────────────

export class CollectionsDashboardDto {
  @ApiProperty({ description: 'Total number of open invoices analysed' })
  totalOpenInvoices!: number;

  @ApiProperty({
    description: 'Total outstanding amount across all open invoices',
  })
  totalOutstandingAmount!: number;

  @ApiProperty({ description: 'Currency' })
  currency!: string;

  @ApiProperty({ description: 'Count of invoices per risk level' })
  riskBreakdown!: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };

  @ApiProperty({ description: 'Outstanding amount per risk level' })
  amountByRisk!: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };

  @ApiProperty({
    type: InvoiceRiskScoreDto,
    isArray: true,
    description: 'Risk scores for all open invoices, sorted by risk descending',
  })
  scores!: InvoiceRiskScoreDto[];
}

// ─── Reminder generation request ────────────────────────────────────────────

export class GenerateReminderResponseDto {
  @ApiProperty({ description: 'Invoice ID the reminder was generated for' })
  invoiceId!: string;

  @ApiProperty({ description: 'Risk level at time of generation' })
  riskLevel!: RiskLevel;

  @ApiProperty({
    description: 'AI-generated reminder message body (in French)',
  })
  reminderMessage!: string;

  @ApiProperty({ description: 'Suggested email subject line' })
  subject!: string;

  @ApiPropertyOptional({ description: 'Recommended follow-up action' })
  recommendedAction?: string;
}
