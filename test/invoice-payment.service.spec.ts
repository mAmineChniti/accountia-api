import { Test, type TestingModule } from '@nestjs/testing';
import { getModelToken, getConnectionToken } from '@nestjs/mongoose';
import { InvoicePaymentService } from '../src/invoices/services/invoice-payment.service';
import { ConfigService } from '@nestjs/config';
import { InvoiceIssuanceService } from '../src/invoices/services/invoice-issuance.service';
import { EmailService } from '../src/email/email.service';
import { NotificationsService } from '../src/notifications/notifications.service';
import { InvoiceStatus } from '../src/invoices/enums/invoice-status.enum';
import { ForbiddenException } from '@nestjs/common';
import { Types } from 'mongoose';
import { type UserPayload } from '../src/auth/types/auth.types';

describe('InvoicePaymentService', () => {
  let service: InvoicePaymentService;
  let mockInvoiceReceiptModel: { findById: jest.Mock; updateOne: jest.Mock };
  let mockIssuanceService: {
    getInvoiceById: jest.Mock;
    transitionInvoiceState: jest.Mock;
  };

  beforeEach(async () => {
    mockInvoiceReceiptModel = {
      findById: jest.fn(),
      updateOne: jest.fn(),
    };

    mockIssuanceService = {
      getInvoiceById: jest.fn(),
      transitionInvoiceState: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        InvoicePaymentService,
        {
          provide: ConfigService,
          useValue: { get: jest.fn().mockReturnValue('mock_key') },
        },
        {
          provide: getModelToken('InvoiceReceipt'),
          useValue: mockInvoiceReceiptModel,
        },
        { provide: getModelToken('Business'), useValue: {} },
        { provide: InvoiceIssuanceService, useValue: mockIssuanceService },
        {
          provide: EmailService,
          useValue: { sendInvoicePaymentConfirmation: jest.fn() },
        },
        {
          provide: NotificationsService,
          useValue: { createNotification: jest.fn() },
        },
        { provide: getConnectionToken(), useValue: {} },
      ],
    }).compile();

    service = module.get<InvoicePaymentService>(InvoicePaymentService);
  });

  it('should throw ForbiddenException if user email does not match recipient email', () => {
    const receipt = {
      recipientEmail: 'other@test.com',
      recipientUserId: new Types.ObjectId(),
    };
    const user = {
      id: 'user1',
      email: 'me@test.com',
    } as unknown as UserPayload;

    // @ts-expect-error - accessing private method
    expect(() => service.assertRecipientCanPay(receipt, user)).toThrow(
      ForbiddenException
    );
  });

  it('should allow payment if user email matches receipt', () => {
    const receipt = {
      recipientEmail: 'me@test.com',
      recipientUserId: new Types.ObjectId(),
    };
    const user = {
      id: 'user1',
      email: 'me@test.com',
    } as unknown as UserPayload;

    // @ts-expect-error - accessing private method
    expect(() => service.assertRecipientCanPay(receipt, user)).not.toThrow();
  });

  it('should correctly identify payable statuses', () => {
    // @ts-expect-error - accessing private method
    expect(service.isPayableStatus(InvoiceStatus.ISSUED)).toBe(true);
    // @ts-expect-error - accessing private method
    expect(service.isPayableStatus(InvoiceStatus.PAID)).toBe(false);
    // @ts-expect-error - accessing private method
    expect(service.isPayableStatus(InvoiceStatus.VOIDED)).toBe(false);
  });

  it('should transition invoice to PAID status on simulation', async () => {
    const receiptId = new Types.ObjectId().toString();
    const user = {
      id: 'user1',
      email: 'me@test.com',
    } as unknown as UserPayload;
    const receipt = {
      invoiceId: new Types.ObjectId(),
      issuerBusinessId: new Types.ObjectId(),
      issuerTenantDatabaseName: 'test_db',
      recipientEmail: 'me@test.com',
      issuerBusinessName: 'Test Corp',
    };
    const invoice = {
      id: 'inv1',
      status: InvoiceStatus.ISSUED,
      totalAmount: 100,
      amountPaid: 0,
      invoiceNumber: 'INV-001',
      currency: 'TND',
    };

    mockInvoiceReceiptModel.findById.mockReturnValue({
      exec: jest.fn().mockResolvedValue(receipt),
    });
    mockIssuanceService.getInvoiceById.mockResolvedValue(invoice);

    // Enable mock payments for test
    // @ts-expect-error - accessing private property
    service.mockInvoicePaymentsEnabled = true;

    await service.simulateIndividualPayment(receiptId, user);

    expect(mockIssuanceService.transitionInvoiceState).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      'test_db',
      expect.objectContaining({ newStatus: InvoiceStatus.PAID }),
      user.id
    );
  });
});
