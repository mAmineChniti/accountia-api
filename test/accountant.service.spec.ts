import { Test, type TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { AccountantService } from '../src/accountant/accountant.service';
import { ServiceUnavailableException } from '@nestjs/common';
import { type InternalCreateAccountingJobPayload } from '../src/accountant/dto';

interface HttpClientMock {
  post: jest.Mock;
  get: jest.Mock;
}

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
  let mockHttpClient: HttpClientMock;

  beforeEach(async () => {
    jest.clearAllMocks();
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
    mockHttpClient = (service as unknown as { httpClient: HttpClientMock })
      .httpClient;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createAccountingJob', () => {
    it('should call the AI service and return job info', async () => {
      const mockResponse = { task_id: 'job_123', status: 'pending' };
      mockHttpClient.post.mockReturnValue({
        json: jest.fn().mockResolvedValue(mockResponse),
      });

      const dto: InternalCreateAccountingJobPayload = {
        business_id: 'b1',
        period_start: '2024-01-01',
        period_end: '2024-01-31',
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
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'AI_ACCOUNTANT_API_KEY') return '';
        return;
      });
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          AccountantService,
          { provide: ConfigService, useValue: mockConfigService },
        ],
      }).compile();
      const disabledService = module.get<AccountantService>(AccountantService);

      const payload: InternalCreateAccountingJobPayload = {
        business_id: 'b1',
        period_start: '2024-01-01',
        period_end: '2024-01-31',
      };

      await expect(
        disabledService.createAccountingJob(payload)
      ).rejects.toThrow(ServiceUnavailableException);
    });
  });

  describe('getJobStatus', () => {
    it('should return the status of a job', async () => {
      const mockStatus = { task_id: 'job_123', status: 'completed' };
      mockHttpClient.get.mockReturnValue({
        json: jest.fn().mockResolvedValue(mockStatus),
      });

      const result = await service.getJobStatus('job_123', 'b1');

      expect(mockHttpClient.get).toHaveBeenCalledWith(
        'api/accounting/jobs/job_123',
        expect.objectContaining({
          searchParams: { business_id: 'b1' },
        })
      );
      expect(result).toEqual(mockStatus);
    });
  });

  describe('getTaxSummary', () => {
    it('should return tax summary for a year', async () => {
      const mockTaxes = { vat: 1000, income_tax: 2000 };
      mockHttpClient.get.mockReturnValue({
        json: jest.fn().mockResolvedValue(mockTaxes),
      });

      const result = await service.getTaxSummary('b1', 2024);

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
      mockHttpClient.get.mockResolvedValue({});

      const result = await service.healthCheck();

      expect(result).toBe(true);
    });

    it('should return false if AI service is down', async () => {
      mockHttpClient.get.mockRejectedValue(new Error('Down'));

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });
  });
});
