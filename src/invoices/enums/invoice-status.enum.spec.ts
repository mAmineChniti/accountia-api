import {
  InvoiceStatus,
  INVOICE_STATUS_TRANSITIONS,
} from './invoice-status.enum';

describe('INVOICE_STATUS_TRANSITIONS', () => {
  it('defines a transition list for every status (including terminal ones)', () => {
    for (const status of Object.values(InvoiceStatus)) {
      expect(INVOICE_STATUS_TRANSITIONS[status]).toBeDefined();
    }
  });

  it('treats ARCHIVED as a terminal state', () => {
    expect(INVOICE_STATUS_TRANSITIONS[InvoiceStatus.ARCHIVED]).toEqual([]);
  });

  it('only allows DRAFT to move to ISSUED or VOIDED', () => {
    expect(INVOICE_STATUS_TRANSITIONS[InvoiceStatus.DRAFT]).toEqual(
      expect.arrayContaining([InvoiceStatus.ISSUED, InvoiceStatus.VOIDED])
    );
    expect(INVOICE_STATUS_TRANSITIONS[InvoiceStatus.DRAFT]).not.toContain(
      InvoiceStatus.PAID
    );
    expect(INVOICE_STATUS_TRANSITIONS[InvoiceStatus.DRAFT]).not.toContain(
      InvoiceStatus.OVERDUE
    );
  });

  it('keeps VOIDED a near-terminal state (only ARCHIVED allowed)', () => {
    expect(INVOICE_STATUS_TRANSITIONS[InvoiceStatus.VOIDED]).toEqual([
      InvoiceStatus.ARCHIVED,
    ]);
  });

  it('does not allow self-transitions for any status', () => {
    for (const [from, targets] of Object.entries(INVOICE_STATUS_TRANSITIONS)) {
      expect(targets).not.toContain(from);
    }
  });

  it('only allows PAID → DISPUTED or PAID → ARCHIVED', () => {
    expect(INVOICE_STATUS_TRANSITIONS[InvoiceStatus.PAID]).toEqual(
      expect.arrayContaining([InvoiceStatus.DISPUTED, InvoiceStatus.ARCHIVED])
    );
    expect(INVOICE_STATUS_TRANSITIONS[InvoiceStatus.PAID]).not.toContain(
      InvoiceStatus.DRAFT
    );
  });

  it('cannot return to DRAFT from any later state', () => {
    for (const [from, targets] of Object.entries(INVOICE_STATUS_TRANSITIONS)) {
      if (from === InvoiceStatus.DRAFT) continue;
      expect(targets).not.toContain(InvoiceStatus.DRAFT);
    }
  });
});
