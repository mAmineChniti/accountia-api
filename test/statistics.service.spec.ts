import { Test, type TestingModule } from '@nestjs/testing';
import { getModelToken, getConnectionToken } from '@nestjs/mongoose';
import { BusinessService } from '../src/business/business.service';
import { Business } from '../src/business/schemas/business.schema';
import { BusinessUser } from '../src/business/schemas/business-user.schema';
import { BusinessInvite } from '../src/business/schemas/business-invite.schema';
import { User } from '../src/users/schemas/user.schema';
import { BusinessApplication } from '../src/business/schemas/business-application.schema';
import { EmailService } from '../src/email/email.service';
import { TenantConnectionService } from '../src/common/tenant/tenant-connection.service';
import { AuditEmitter } from '../src/audit/audit.emitter';
import { NotificationsService } from '../src/notifications/notifications.service';
import { ConfigService } from '@nestjs/config';
import { CacheService } from '../src/redis/cache.service';
import { TensorflowPredictionService } from '../src/business/services/tensorflow-prediction.service';
import { Role } from '../src/auth/enums/role.enum';
import { Types } from 'mongoose';
import { NotFoundException } from '@nestjs/common';

describe('BusinessService (Statistics)', () => {
  let service: BusinessService;
  let mockBusinessModel: { findById: jest.Mock };
  let mockCacheService: { get: jest.Mock; set: jest.Mock };
  let mockTensorflowService: { forecastBusinessMetrics: jest.Mock };
  let mockConnection: { useDb: jest.Mock };

  const businessId = new Types.ObjectId().toString();
  const userId = new Types.ObjectId().toString();
  const databaseName = 'tenant_business_1';

  beforeEach(async () => {
    mockBusinessModel = {
      findById: jest.fn(),
    };

    mockCacheService = {
      get: jest.fn().mockResolvedValue(),
      set: jest.fn().mockResolvedValue(true),
    };

    mockTensorflowService = {
      forecastBusinessMetrics: jest.fn().mockResolvedValue({
        revenue: {
          historical: [{ date: '2024-01-01', value: 1000 }],
          forecast: [],
        },
        cogs: {
          historical: [{ date: '2024-01-01', value: 500 }],
          forecast: [],
        },
        salesVolume: { historical: [], forecast: [] },
      }),
    };

    mockConnection = {
      useDb: jest.fn().mockReturnValue({
        collection: jest.fn().mockReturnValue({
          aggregate: jest.fn().mockReturnValue({
            toArray: jest.fn().mockResolvedValue([]),
          }),
          find: jest.fn().mockReturnValue({
            toArray: jest.fn().mockResolvedValue([]),
          }),
        }),
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BusinessService,
        {
          provide: getModelToken(Business.name),
          useValue: mockBusinessModel,
        },
        {
          provide: getModelToken(BusinessUser.name),
          useValue: {
            findOne: jest
              .fn()
              .mockResolvedValue({ userId, businessId, role: 'OWNER' }),
          },
        },
        {
          provide: getModelToken(BusinessInvite.name),
          useValue: {},
        },
        {
          provide: getModelToken(User.name),
          useValue: {
            findOne: jest
              .fn()
              .mockResolvedValue({ _id: userId, email: 'owner@test.com' }),
          },
        },
        {
          provide: getModelToken(BusinessApplication.name),
          useValue: {},
        },
        {
          provide: CacheService,
          useValue: mockCacheService,
        },
        {
          provide: TensorflowPredictionService,
          useValue: mockTensorflowService,
        },
        {
          provide: getConnectionToken(),
          useValue: mockConnection,
        },
        { provide: EmailService, useValue: {} },
        { provide: TenantConnectionService, useValue: {} },
        { provide: AuditEmitter, useValue: { emitAction: jest.fn() } },
        { provide: NotificationsService, useValue: {} },
        { provide: ConfigService, useValue: { get: jest.fn() } },
      ],
    }).compile();

    service = module.get<BusinessService>(BusinessService);
  });

  it('should return statistics from cache if available', async () => {
    const mockCachedData = { businessId, kpis: { totalRevenue: 100 } };
    mockCacheService.get.mockResolvedValue(mockCachedData);

    const result = await service.getBusinessStatistics(
      businessId,
      userId,
      Role.CLIENT
    );

    expect(result.kpis.totalRevenue).toBe(100);
    expect(mockBusinessModel.findById).not.toHaveBeenCalled();
    expect(mockConnection.useDb).not.toHaveBeenCalled();
    expect(
      mockTensorflowService.forecastBusinessMetrics
    ).not.toHaveBeenCalled();
    // Ensure we returned a clone of cached data, not the same reference
    expect(result).not.toBe(mockCachedData);
    expect(mockCacheService.get).toHaveBeenCalledWith(
      `business:statistics:${businessId}:90`
    );
  });

  it('should calculate statistics and cache them if not cached', async () => {
    mockBusinessModel.findById.mockResolvedValue({
      _id: businessId,
      databaseName,
    });

    // Mock Aggregation Results
    const mockInvoiceAgg = [
      {
        totalInvoices: 10,
        paidInvoices: 5,
        pendingInvoices: 5,
        paidAmount: 5000,
        pendingAmount: 5000,
      },
    ];

    const mockLineItemAgg = [{ productId: 'p1', quantity: 10, revenue: 1000 }];

    const mockProducts = [
      { _id: 'p1', name: 'Product 1', unitPrice: 100, cost: 50, quantity: 20 },
    ];

    const mockCollection = {
      aggregate: jest.fn().mockReturnValue({
        toArray: jest
          .fn()
          .mockResolvedValueOnce(mockInvoiceAgg)
          .mockResolvedValueOnce(mockLineItemAgg),
      }),
      find: jest.fn().mockReturnValue({
        toArray: jest.fn().mockResolvedValue(mockProducts),
      }),
    };

    mockConnection.useDb.mockReturnValue({
      collection: jest.fn().mockImplementation(() => mockCollection),
    });

    const result = await service.getBusinessStatistics(
      businessId,
      userId,
      Role.CLIENT
    );

    expect(result.businessId).toBe(businessId);
    expect(result.invoiceStatistics.totalInvoices).toBe(10);
    expect(result.productStatistics.totalProducts).toBe(1);
    expect(result.productStatistics.totalInventoryValue).toBe(2000); // 100 * 20
    expect(mockCacheService.set).toHaveBeenCalledWith(
      `business:statistics:${businessId}:90`,
      expect.any(Object),
      300
    );
  });

  it('should throw NotFoundException if business not found', async () => {
    mockBusinessModel.findById.mockResolvedValue(undefined as never);

    await expect(
      service.getBusinessStatistics(businessId, userId, Role.CLIENT)
    ).rejects.toThrow(NotFoundException);
    expect(mockBusinessModel.findById).toHaveBeenCalledWith(businessId);
  });
});
