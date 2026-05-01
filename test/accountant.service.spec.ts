import { Test, type TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import type ky from 'ky';
import { AccountantService } from '../src/accountant/accountant.service';
import { ServiceUnavailableException } from '@nestjs/common';
import { type InternalCreateAccountingJobPayload } from '../src/accountant/dto';

type KyInstance = ReturnType<typeof ky.create>;

// Mock ky
jest.mock('ky', () => ({
  create: jest.fn().mockReturnValue({
    post: jest.fn(),
    get: jest.fn(),
  }),
}));

describe('AccountantService', () => {
  let service: AccountantService;
  let mockConfigService: { get: jest.Mock };
  let mockHttpClient: jest.Mocked<KyInstance>;

  beforeEach(async () => {
    jest.resetAllMocks();
    mockConfigService = {
      get: jest.fn((key: string, defaultValue?: unknown) => {
        if (key === 'AI_ACCOUNTANT_URL') return 'http://test-ai:8000';
        if (key === 'AI_ACCOUNTANT_API_KEY') return 'test-api-key';
        return defaultValue;
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AccountantService,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<AccountantService>(AccountantService);
    // Access the private httpClient for mocking calls
    mockHttpClient = (
      service as unknown as { httpClient: jest.Mocked<KyInstance> }
    ).httpClient;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createAccountingJob', () => {
    it('should call the AI service and return job info', async () => {
      const mockResponse = { taskId: 'job_123', status: 'pending' };
      const mockPostResp = {
        json: jest
          .fn<Promise<{ taskId: string; status: string }>, []>()
          .mockResolvedValue(mockResponse),
      };
      mockHttpClient.post.mockImplementation(
        () => mockPostResp as unknown as ReturnType<KyInstance['post']>
      );

      const dto: InternalCreateAccountingJobPayload = {
        businessId: 'b1',
        periodStart: '2024-01-01',
        periodEnd: '2024-01-31',
      };
      const result = await service.createAccountingJob(dto);

      expect(mockHttpClient.post).toHaveBeenCalledWith(
        'api/accounting/jobs',
        expect.objectContaining({
          json: dto,
        })
      );
      expect(result).toEqual(mockResponse);
    });

    it('should throw ServiceUnavailableException if API key is missing', async () => {
      // Re-instantiate service without API key
      mockConfigService.get.mockImplementation(
        (key: string, defaultValue?: unknown) => {
          if (key === 'AI_ACCOUNTANT_API_KEY') return '';
          if (key === 'AI_ACCOUNTANT_URL') return 'http://test-ai:8000';
          return defaultValue;
        }
      );
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          AccountantService,
          { provide: ConfigService, useValue: mockConfigService },
        ],
      }).compile();
      const disabledService = module.get<AccountantService>(AccountantService);

      const payload: InternalCreateAccountingJobPayload = {
        businessId: 'b1',
        periodStart: '2024-01-01',
        periodEnd: '2024-01-31',
      };

      await expect(
        disabledService.createAccountingJob(payload)
      ).rejects.toThrow(ServiceUnavailableException);
    });
  });

  describe('getJobStatus', () => {
    it('should return the status of a job', async () => {
      const mockStatus = { taskId: 'job_123', status: 'completed' };
      const mockGetResp = {
        json: jest
          .fn<Promise<{ taskId: string; status: string }>, []>()
          .mockResolvedValue(mockStatus),
      };
      mockHttpClient.get.mockImplementation(
        () => mockGetResp as unknown as ReturnType<KyInstance['get']>
      );

      const result = await service.getJobStatus('job_123', 'b1');

      expect(mockHttpClient.get).toHaveBeenCalledWith(
        'api/accounting/jobs/job_123',
        expect.objectContaining({
          searchParams: { businessId: 'b1' },
        })
      );
      expect(result).toEqual(mockStatus);
    });
  });

  describe('getTaxSummary', () => {
    it('should return tax summary for a year', async () => {
      const mockTaxes = { vat: 1000, income_tax: 2000 };
      const mockGetTaxesResp = {
        json: jest
          .fn<Promise<Record<string, number>>, []>()
          .mockResolvedValue(mockTaxes),
      };
      mockHttpClient.get.mockImplementation(
        () => mockGetTaxesResp as unknown as ReturnType<KyInstance['get']>
      );

      const result = await service.getTaxSummary('b1', '2024');

      expect(mockHttpClient.get).toHaveBeenCalledWith(
        'api/accounting/business/b1/taxes',
        expect.objectContaining({
          searchParams: { year: '2024' },
        })
      );
      expect(result).toEqual(mockTaxes);
    });
  });

  describe('healthCheck', () => {
    it('should return true if AI service is healthy', async () => {
      const mockHealthResp = {
        json: jest
          .fn<Promise<{ status: string }>, []>()
          .mockResolvedValue({ status: 'healthy' }),
      };
      mockHttpClient.get.mockImplementation(
        () => mockHealthResp as unknown as ReturnType<KyInstance['get']>
      );

      const result = await service.healthCheck();

      expect(result).toBe(true);
      expect(mockHttpClient.get).toHaveBeenCalledWith('api/health', {
        timeout: 5000,
      });
    });

    it('should return false if AI service reports non-healthy status', async () => {
      const mockHealthResp = {
        json: jest
          .fn<Promise<{ status: string }>, []>()
          .mockResolvedValue({ status: 'unavailable' }),
      };
      mockHttpClient.get.mockImplementation(
        () => mockHealthResp as unknown as ReturnType<KyInstance['get']>
      );

      const result = await service.healthCheck();

      expect(result).toBe(false);
      expect(mockHttpClient.get).toHaveBeenCalledWith('api/health', {
        timeout: 5000,
      });
    });

    it('should return false if AI service is down', async () => {
      mockHttpClient.get.mockRejectedValue(new Error('Down'));

      const result = await service.healthCheck();

      expect(result).toBe(false);
      expect(mockHttpClient.get).toHaveBeenCalledWith('api/health', {
        timeout: 5000,
      });
    });
  });
});
