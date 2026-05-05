import { Test, type TestingModule } from '@nestjs/testing';
import { getConnectionToken } from '@nestjs/mongoose';
import { TensorflowPredictionService } from '../src/business/services/tensorflow-prediction.service';
import { CacheService } from '../src/redis/cache.service';
import { Types } from 'mongoose';
import { InvoiceStatus } from '../src/invoices/enums/invoice-status.enum';
import { type Invoice } from '../src/invoices/schemas/invoice.schema';

describe('TensorflowPredictionService', () => {
  let service: TensorflowPredictionService;
  let mockCacheService: { get: jest.Mock; set: jest.Mock };
  let mockConnection: { useDb: jest.Mock };

  const businessId = new Types.ObjectId().toString();
  const databaseName = 'tenant_db_test';
  const horizonMonths = 3;

  beforeEach(async () => {
    mockCacheService = {
      get: jest.fn(),
      set: jest.fn(),
    };

    mockConnection = {
      useDb: jest.fn().mockReturnValue({
        collection: jest.fn().mockReturnValue({
          find: jest.fn().mockReturnValue({
            sort: jest.fn().mockReturnValue({
              toArray: jest.fn().mockResolvedValue([]),
            }),
            toArray: jest.fn().mockResolvedValue([]),
          }),
        }),
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TensorflowPredictionService,
        {
          provide: CacheService,
          useValue: mockCacheService,
        },
        {
          provide: getConnectionToken(),
          useValue: mockConnection,
        },
      ],
    }).compile();

    service = module.get<TensorflowPredictionService>(
      TensorflowPredictionService
    );
  });

  it('should return cached forecast if available', async () => {
    const mockForecast = { revenue: { historical: [], predicted: [] } };
    mockCacheService.get.mockResolvedValue(mockForecast);

    const result = await service.forecastBusinessMetrics(
      businessId,
      databaseName,
      horizonMonths
    );

    expect(result).toEqual(mockForecast);
    expect(mockCacheService.get).toHaveBeenCalled();
  });

  it('should use linear extrapolation when data points are insufficient', async () => {
    const historical = [
      { date: '2024-01', value: 100 },
      { date: '2024-02', value: 200 },
    ];

    const result = await service.forecastMetric(historical, 1);

    expect(result).toHaveLength(1);
    expect(result[0].date).toBe('2024-03');
    expect(result[0].value).toBeGreaterThan(200); // 100 -> 200 -> prediction > 200
  });

  it('should calculate revenue correctly for PARTIAL invoices', () => {
    const invoices = [
      {
        issuedDate: new Date('2024-01-15'),
        status: InvoiceStatus.PARTIAL,
        totalAmount: 1000,
        amountPaid: 400,
        lineItems: [
          {
            quantity: 1,
            unitPrice: 1000,
            productId: new Types.ObjectId().toString(),
          },
        ],
      },
    ] as unknown as Invoice[];

    const productCostMap = new Map<string, number>();
    // @ts-expect-error - accessing private method
    const monthlyData = service.buildMonthlyTimeSeries(
      invoices,
      productCostMap
    ) as Map<string, { revenue: number }>;
    const janData = monthlyData.get('2024-01');

    // Revenue must be 400 (40% of 1000 because paid amount is 400)
    expect(janData?.revenue).toBe(400);
  });
});
