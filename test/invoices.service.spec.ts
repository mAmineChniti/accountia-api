import { Test, type TestingModule } from '@nestjs/testing';
import { getModelToken, getConnectionToken } from '@nestjs/mongoose';
import { InvoiceIssuanceService } from '../src/invoices/services/invoice-issuance.service';
import { TenantConnectionService } from '../src/common/tenant/tenant-connection.service';
import { NotificationsService } from '../src/notifications/notifications.service';
import { InvoiceReceipt } from '../src/invoices/schemas/invoice-receipt.schema';
import { Business } from '../src/business/schemas/business.schema';
import { InvoiceStatus } from '../src/invoices/enums/invoice-status.enum';
import { Types } from 'mongoose';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { ObjectId } from 'mongodb';

describe('InvoiceIssuanceService', () => {
  let service: InvoiceIssuanceService;
  let mockInvoiceReceiptModel: {
    findOne: jest.Mock;
    create: jest.Mock;
    updateOne: jest.Mock;
    exec: jest.Mock;
  };
  let mockBusinessModel: { findById: jest.Mock; exec: jest.Mock };
  let mockConnection: { useDb: jest.Mock; db: { collection: jest.Mock } };
  let mockTenantConnectionService: { getTenantModel: jest.Mock };
  let mockNotificationsService: { createNotification: jest.Mock };
  let mockInvoiceModel: Record<string, jest.Mock>;
  let mockProductsCollection: { findOne: jest.Mock; updateOne: jest.Mock };
  let mockTenantDb: { collection: jest.Mock };

  const businessId = new Types.ObjectId().toString();
  const databaseName = 'tenant_db';
  const userId = new Types.ObjectId().toString();

  const createMockInvoice = (overrides = {}) => {
    const id = new Types.ObjectId();
    const bizId = new Types.ObjectId(businessId);
    const uId = new Types.ObjectId(userId);

    return {
      _id: id,
      issuerBusinessId: bizId,
      invoiceNumber: 'INV-20250404-TEST',
      recipient: {
        type: 'EXTERNAL',
        email: 'test@example.com',
        displayName: 'Test Recipient',
        resolutionStatus: 'PENDING',
      },
      status: InvoiceStatus.DRAFT,
      totalAmount: 100,
      currency: 'TND',
      amountPaid: 0,
      lineItems: [
        {
          _id: new Types.ObjectId(),
          productId: new Types.ObjectId(),
          productName: 'P1',
          quantity: 2,
          unitPrice: 50,
          amount: 100,
        },
      ],
      createdBy: uId,
      lastModifiedBy: uId,
      createdAt: new Date(),
      updatedAt: new Date(),
      save: jest.fn().mockResolvedValue(this),
      ...overrides,
    };
  };

  beforeEach(async () => {
    mockInvoiceModel = {
      create: jest.fn(),
      find: jest.fn().mockReturnThis(),
      findById: jest.fn().mockReturnThis(),
      countDocuments: jest.fn(),
      skip: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      sort: jest.fn().mockReturnThis(),
      exec: jest.fn(),
      save: jest.fn(),
    };

    mockProductsCollection = {
      findOne: jest.fn(),
      updateOne: jest.fn(),
    };

    mockTenantDb = {
      collection: jest.fn().mockImplementation((name: string) => {
        if (name === 'products') return mockProductsCollection;
        return;
      }),
    };

    mockConnection = {
      useDb: jest.fn().mockReturnValue(mockTenantDb),
      db: {
        collection: jest.fn().mockReturnValue({
          updateOne: jest.fn(),
        }),
      },
    };

    mockInvoiceReceiptModel = {
      findOne: jest.fn().mockReturnThis(),
      create: jest.fn().mockImplementation((data) => ({
        ...data,
        _id: new Types.ObjectId(),
      })),
      updateOne: jest.fn(),
      exec: jest.fn(),
    };

    mockBusinessModel = {
      findById: jest.fn().mockReturnThis(),
      exec: jest.fn(),
    };

    mockTenantConnectionService = {
      getTenantModel: jest
        .fn()
        .mockImplementation(({ modelName }: { modelName: string }) => {
          if (modelName === 'Invoice') return mockInvoiceModel;
          return;
        }),
    };

    mockNotificationsService = {
      createNotification: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        InvoiceIssuanceService,
        {
          provide: getModelToken(InvoiceReceipt.name),
          useValue: mockInvoiceReceiptModel,
        },
        {
          provide: getModelToken(Business.name),
          useValue: mockBusinessModel,
        },
        {
          provide: getConnectionToken(),
          useValue: mockConnection,
        },
        {
          provide: TenantConnectionService,
          useValue: mockTenantConnectionService,
        },
        {
          provide: NotificationsService,
          useValue: mockNotificationsService,
        },
      ],
    }).compile();

    service = module.get<InvoiceIssuanceService>(InvoiceIssuanceService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createDraftInvoice', () => {
    it('should create a draft invoice and sync to platform', async () => {
      const dto = {
        recipient: {
          type: 'EXTERNAL',
          email: 'test@example.com',
          displayName: 'Test Recipient',
        },
        lineItems: [
          {
            productId: 'prod1',
            productName: 'Product 1',
            quantity: 2,
            unitPrice: 50,
          },
        ],
        currency: 'TND',
      };

      const mockProduct = {
        _id: new ObjectId(),
        name: 'Product 1',
        quantity: 10,
      };
      mockProductsCollection.findOne.mockResolvedValue(mockProduct);
      mockProductsCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const mockCreatedInvoice = createMockInvoice(dto);
      mockInvoiceModel.create.mockResolvedValue(mockCreatedInvoice);
      mockBusinessModel.findById.mockReturnThis();
      mockBusinessModel.exec.mockResolvedValue({ name: 'My Business' });

      const result = await service.createDraftInvoice(
        businessId,
        databaseName,
        dto as any,
        userId
      );

      expect(mockInvoiceModel.create).toHaveBeenCalled();
      expect(result.status).toBe(InvoiceStatus.DRAFT);
      expect(mockConnection.db.collection).toHaveBeenCalledWith('invoices');
    });

    it('should rollback if product reservation fails', async () => {
      const dto = {
        recipient: { type: 'EXTERNAL', email: 'test@example.com' },
        lineItems: [{ productId: 'prod1', quantity: 100, unitPrice: 10 }],
      };

      mockProductsCollection.findOne.mockResolvedValue({
        _id: new ObjectId(),
        name: 'P1',
        quantity: 10,
      });
      mockProductsCollection.updateOne.mockResolvedValue({ modifiedCount: 0 });

      await expect(
        service.createDraftInvoice(businessId, databaseName, dto as any, userId)
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('getIssuerInvoices', () => {
    it('should return paginated invoices', async () => {
      const mockInvoices = [createMockInvoice()];
      mockInvoiceModel.countDocuments
        .mockResolvedValueOnce(10)
        .mockResolvedValueOnce(1);
      mockInvoiceModel.find.mockReturnThis();
      mockInvoiceModel.exec.mockResolvedValue(mockInvoices);

      const result = await service.getIssuerInvoices(
        businessId,
        databaseName,
        1,
        10
      );

      expect(result.total).toBe(10);
      expect(result.filteredTotal).toBe(1);
      expect(result.invoices.length).toBe(1);
    });
  });

  describe('transitionInvoiceState', () => {
    it('should transition DRAFT to ISSUED and send notification', async () => {
      const invoiceId = new Types.ObjectId().toString();
      const mockInvoice = createMockInvoice({
        _id: new Types.ObjectId(invoiceId),
        status: InvoiceStatus.DRAFT,
      });

      mockInvoiceModel.findById.mockReturnThis();
      mockInvoiceModel.exec.mockResolvedValue(mockInvoice);
      mockBusinessModel.findById.mockReturnThis();
      mockBusinessModel.exec.mockResolvedValue({ name: 'Biz' });

      await service.transitionInvoiceState(
        invoiceId,
        businessId,
        databaseName,
        { newStatus: InvoiceStatus.ISSUED },
        userId
      );

      expect(mockInvoice.status).toBe(InvoiceStatus.ISSUED);
      expect(mockNotificationsService.createNotification).toHaveBeenCalled();
      expect(mockInvoiceReceiptModel.create).toHaveBeenCalled();
    });

    it('should throw error for invalid transition', async () => {
      const invoiceId = new Types.ObjectId().toString();
      const mockInvoice = createMockInvoice({
        _id: new Types.ObjectId(invoiceId),
        status: InvoiceStatus.PAID,
      });

      mockInvoiceModel.findById.mockReturnThis();
      mockInvoiceModel.exec.mockResolvedValue(mockInvoice);

      await expect(
        service.transitionInvoiceState(
          invoiceId,
          businessId,
          databaseName,
          { newStatus: InvoiceStatus.ISSUED },
          userId
        )
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('updateDraftInvoice', () => {
    it('should update a draft invoice', async () => {
      const invoiceId = new Types.ObjectId().toString();
      const mockInvoice = createMockInvoice({
        _id: new Types.ObjectId(invoiceId),
        status: InvoiceStatus.DRAFT,
      });

      mockInvoiceModel.findById.mockReturnThis();
      mockInvoiceModel.exec.mockResolvedValue(mockInvoice);

      const dto = { description: 'Updated' };
      const result = await service.updateDraftInvoice(
        invoiceId,
        businessId,
        databaseName,
        dto,
        userId
      );

      expect(mockInvoice.save).toHaveBeenCalled();
      expect(result).toBeDefined();
    });

    it('should throw ForbiddenException if user does not own invoice', async () => {
      const invoiceId = new Types.ObjectId().toString();
      const mockInvoice = createMockInvoice({ issuerBusinessId: 'other-biz' });
      mockInvoiceModel.findById.mockReturnThis();
      mockInvoiceModel.exec.mockResolvedValue(mockInvoice);

      await expect(
        service.updateDraftInvoice(
          invoiceId,
          businessId,
          databaseName,
          {},
          userId
        )
      ).rejects.toThrow(ForbiddenException);
    });
  });
});
