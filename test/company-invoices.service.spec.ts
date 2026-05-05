import { Test, type TestingModule } from '@nestjs/testing';
import { getModelToken, getConnectionToken } from '@nestjs/mongoose';
import { InvoiceReceiptService } from '../src/invoices/services/invoice-receipt.service';
import { TenantConnectionService } from '../src/common/tenant/tenant-connection.service';
import { InvoiceReceipt } from '../src/invoices/schemas/invoice-receipt.schema';
import { Invoice } from '../src/invoices/schemas/invoice.schema';
import { Types } from 'mongoose';
import { ForbiddenException } from '@nestjs/common';

describe('InvoiceReceiptService', () => {
  let service: InvoiceReceiptService;
  let mockInvoiceReceiptModel: Record<string, jest.Mock>;
  let mockInvoiceModel: Record<string, jest.Mock>;
  let mockConnection: Record<string, unknown>;
  let mockTenantConnectionService: { getTenantModel: jest.Mock };

  const recipientBusinessId = new Types.ObjectId().toString();
  const userId = new Types.ObjectId().toString();
  const userEmail = 'recipient@example.com';

  const createMockReceipt = (overrides: Partial<InvoiceReceipt> = {}) => ({
    _id: new Types.ObjectId(),
    invoiceId: new Types.ObjectId(),
    issuerBusinessId: new Types.ObjectId(),
    issuerBusinessName: 'Issuer Biz',
    invoiceNumber: 'INV-001',
    totalAmount: 1000,
    currency: 'TND',
    issuedDate: new Date(),
    dueDate: new Date(),
    invoiceStatus: 'ISSUED',
    recipientViewed: false,
    lastSyncedAt: new Date(),
    createdAt: new Date(),
    recipientBusinessId: new Types.ObjectId(recipientBusinessId),
    ...overrides,
  });

  beforeEach(async () => {
    mockInvoiceReceiptModel = {
      find: jest.fn().mockReturnThis(),
      findById: jest.fn().mockReturnThis(),
      countDocuments: jest.fn(),
      skip: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      sort: jest.fn().mockReturnThis(),
      lean: jest.fn().mockReturnThis(),
      exec: jest.fn(),
      updateOne: jest.fn().mockResolvedValue({ modifiedCount: 1 }),
    };

    mockInvoiceModel = {
      findById: jest.fn().mockReturnThis(),
      exec: jest.fn(),
    };

    mockConnection = {};

    mockTenantConnectionService = {
      getTenantModel: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        InvoiceReceiptService,
        {
          provide: getModelToken(InvoiceReceipt.name),
          useValue: mockInvoiceReceiptModel,
        },
        {
          provide: getModelToken(Invoice.name),
          useValue: mockInvoiceModel,
        },
        {
          provide: getConnectionToken(),
          useValue: mockConnection,
        },
        {
          provide: TenantConnectionService,
          useValue: mockTenantConnectionService,
        },
      ],
    }).compile();

    service = module.get<InvoiceReceiptService>(InvoiceReceiptService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getReceivedInvoicesByBusiness', () => {
    it('should return paginated receipts for a business', async () => {
      const mockReceipts = [createMockReceipt()];
      mockInvoiceReceiptModel.countDocuments
        .mockResolvedValueOnce(5)
        .mockResolvedValueOnce(1);
      mockInvoiceReceiptModel.exec.mockResolvedValue(mockReceipts);

      const result = await service.getReceivedInvoicesByBusiness(
        recipientBusinessId,
        1,
        10
      );

      expect(result.total).toBe(5);
      expect(result.receipts.length).toBe(1);
      expect(result.receipts[0].issuerBusinessName).toBe('Issuer Biz');
    });
  });

  describe('getReceivedInvoicesByIndividual', () => {
    it('should return receipts matching userId or email', async () => {
      const mockReceipts = [createMockReceipt({ recipientUserId: userId })];
      mockInvoiceReceiptModel.countDocuments
        .mockResolvedValueOnce(2)
        .mockResolvedValueOnce(1);
      mockInvoiceReceiptModel.exec.mockResolvedValue(mockReceipts);

      const result = await service.getReceivedInvoicesByIndividual(
        userId,
        userEmail,
        1,
        10
      );

      expect(result.total).toBe(2);
      expect(mockInvoiceReceiptModel.find).toHaveBeenCalledWith(
        expect.objectContaining({
          $or: [
            { recipientUserId: userId },
            { recipientEmail: userEmail.toLowerCase() },
          ],
        })
      );
    });
  });

  describe('getInvoiceDetailsAsRecipient', () => {
    it('should return full invoice details and mark as viewed', async () => {
      const receiptId = new Types.ObjectId().toString();
      const mockReceipt = createMockReceipt({
        _id: new Types.ObjectId(receiptId),
        issuerTenantDatabaseName: 'issuer_db',
      });
      const mockInvoice = {
        _id: mockReceipt.invoiceId,
        issuerBusinessId: mockReceipt.issuerBusinessId,
        invoiceNumber: mockReceipt.invoiceNumber,
        recipient: { type: 'PLATFORM_BUSINESS' },
        lineItems: [],
        status: 'ISSUED',
      };

      mockInvoiceReceiptModel.exec.mockResolvedValue(mockReceipt);

      const mockIssuerModel = {
        findById: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue(mockInvoice),
      };
      mockTenantConnectionService.getTenantModel.mockReturnValue(
        mockIssuerModel
      );

      const result = await service.getInvoiceDetailsAsRecipient(
        receiptId,
        recipientBusinessId
      );

      expect(result.invoiceNumber).toBe(mockInvoice.invoiceNumber);
      expect(mockInvoiceReceiptModel.updateOne).toHaveBeenCalledWith(
        { _id: receiptId },
        expect.objectContaining({ recipientViewed: true })
      );
    });

    it('should throw ForbiddenException if recipient mismatch', async () => {
      const receiptId = new Types.ObjectId().toString();
      const mockReceipt = createMockReceipt({
        recipientBusinessId: 'other-biz',
      });
      mockInvoiceReceiptModel.exec.mockResolvedValue(mockReceipt);

      await expect(
        service.getInvoiceDetailsAsRecipient(receiptId, recipientBusinessId)
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw ForbiddenException for external recipient without platform identity', async () => {
      const receiptId = new Types.ObjectId().toString();
      const mockReceipt = createMockReceipt({
        recipientEmail: 'external@example.com',
        recipientUserId: undefined,
        recipientBusinessId: undefined,
      });
      mockInvoiceReceiptModel.exec.mockResolvedValue(mockReceipt);

      await expect(
        service.getInvoiceDetailsAsRecipient(
          receiptId,
          undefined,
          undefined,
          'external@example.com'
        )
      ).rejects.toThrow(ForbiddenException);
    });
  });
});
