/**
 * Invoice Status Enum
 * Represents the lifecycle states of an invoice
 */
export enum InvoiceStatus {
  DRAFT = 'DRAFT', // Invoice prepared but not yet published
  ISSUED = 'ISSUED', // Published to recipient
  VIEWED = 'VIEWED', // Recipient has seen it
  PAID = 'PAID', // Full payment received
  PARTIAL = 'PARTIAL', // Partial payment received
  OVERDUE = 'OVERDUE', // Past due date without full payment
  DISPUTED = 'DISPUTED', // Recipient disputes the amount
  VOIDED = 'VOIDED', // Issuer voided the invoice
  ARCHIVED = 'ARCHIVED', // Kept for historical record
  PENDING_REVIEW = 'PENDING_REVIEW', // PDF import needs manual check
}

/**
 * Valid state transitions for invoices
 * Defines which states an invoice can transition to from each current state
 */
export const INVOICE_STATUS_TRANSITIONS: Record<
  InvoiceStatus,
  InvoiceStatus[]
> = {
  [InvoiceStatus.DRAFT]: [InvoiceStatus.ISSUED, InvoiceStatus.VOIDED],
  [InvoiceStatus.ISSUED]: [
    InvoiceStatus.VIEWED,
    InvoiceStatus.PARTIAL,
    InvoiceStatus.PAID,
    InvoiceStatus.OVERDUE,
    InvoiceStatus.DISPUTED,
    InvoiceStatus.VOIDED,
    InvoiceStatus.ARCHIVED,
  ],
  [InvoiceStatus.VIEWED]: [
    InvoiceStatus.PARTIAL,
    InvoiceStatus.PAID,
    InvoiceStatus.OVERDUE,
    InvoiceStatus.DISPUTED,
    InvoiceStatus.VOIDED,
    InvoiceStatus.ARCHIVED,
  ],
  [InvoiceStatus.PARTIAL]: [
    InvoiceStatus.PAID,
    InvoiceStatus.OVERDUE,
    InvoiceStatus.DISPUTED,
    InvoiceStatus.VOIDED,
    InvoiceStatus.ARCHIVED,
  ],
  [InvoiceStatus.PAID]: [InvoiceStatus.DISPUTED, InvoiceStatus.ARCHIVED],
  [InvoiceStatus.OVERDUE]: [
    InvoiceStatus.PARTIAL,
    InvoiceStatus.PAID,
    InvoiceStatus.DISPUTED,
    InvoiceStatus.VOIDED,
    InvoiceStatus.ARCHIVED,
  ],
  [InvoiceStatus.DISPUTED]: [
    InvoiceStatus.PAID,
    InvoiceStatus.OVERDUE,
    InvoiceStatus.VOIDED,
    InvoiceStatus.ARCHIVED,
  ],
  [InvoiceStatus.VOIDED]: [InvoiceStatus.ARCHIVED],
  [InvoiceStatus.ARCHIVED]: [],
  [InvoiceStatus.PENDING_REVIEW]: [
    InvoiceStatus.DRAFT,
    InvoiceStatus.ISSUED,
    InvoiceStatus.VOIDED,
  ],
};
