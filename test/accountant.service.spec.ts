import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { ServiceUnavailableException, NotFoundException } from '@nestjs/common';
import { type ConfigService } from '@nestjs/config';
import type { InternalCreateAccountingJobPayload } from '../src/accountant/dto/create-job.dto';

// Shared mocked ky instance used by the service under test
const mockKyInstance: {
  post: ReturnType<typeof jest.fn>;
  get: ReturnType<typeof jest.fn>;
} = {
  post: jest.fn(),
  get: jest.fn(),
};

// Simple HTTPError mock that matches shape used by AccountantService
class MockHTTPError extends Error {
  response: unknown;
  constructor(response: unknown) {
    super('HTTPError');
    this.name = 'MockHTTPError';
    this.response = response;
  }
}

// Mock the `ky` module before importing the service so the constructor's
// call to `ky.create()` returns our `mockKyInstance`.
jest.mock('ky', () => ({
  __esModule: true,
  default: { create: jest.fn(() => mockKyInstance) },
  HTTPError: MockHTTPError,
}));

import { AccountantService } from '../src/accountant/accountant.service';

describe('AccountantService', () => {
  let configService: Partial<ConfigService>;
  let svc: AccountantService;

  beforeEach(() => {
    jest.clearAllMocks();

    configService = {
      get: (key: string, defaultValue?: unknown) => {
        if (key === 'AI_ACCOUNTANT_URL') return 'http://localhost:8000';
        if (key === 'AI_ACCOUNTANT_API_KEY') return 'test-key';
        if (key === 'AI_ACCOUNTANT_TIMEOUT_MS') return 1000;
        return defaultValue;
      },
    };

    svc = new AccountantService(configService as ConfigService);
  });

  it('createAccountingJob - returns upstream response on success', async () => {
    const expected = { jobId: 'abc123' };
    mockKyInstance.post.mockResolvedValueOnce({
      json: () => Promise.resolve(expected),
    });

    const dto: InternalCreateAccountingJobPayload = {
      businessId: 'b1',
      periodStart: '2024-01-01T00:00:00Z',
      periodEnd: '2024-01-31T23:59:59Z',
    };
    const res = await svc.createAccountingJob(dto);
    expect(res).toEqual(expected);
    expect(mockKyInstance.post).toHaveBeenCalledWith('api/accounting/jobs', {
      json: dto,
    });
  });

  it('getJobResults - returns result on success', async () => {
    const expected = { taskId: 't1', status: 'completed' };
    mockKyInstance.get.mockResolvedValueOnce({
      json: () => Promise.resolve(expected),
    });

    const res = await svc.getJobResults('t1', 'b1');
    expect(res).toEqual(expected);
    expect(mockKyInstance.get).toHaveBeenCalledWith('api/accounting/jobs/t1', {
      searchParams: { businessId: 'b1' },
    });
  });

  it('healthCheck - returns health response', async () => {
    const expected = { status: 'ok' };
    mockKyInstance.get.mockResolvedValueOnce({
      json: () => Promise.resolve(expected),
    });

    const res = await svc.healthCheck();
    expect(res).toEqual(expected);
    expect(mockKyInstance.get).toHaveBeenCalledWith('api/health');
  });

  it('createAccountingJob - maps 404 to NotFoundException', async () => {
    const err = new MockHTTPError({
      status: 404,
      headers: {
        get: (h: string) => (h === 'x-correlation-id' ? 'cid-1' : undefined),
      },
    });
    mockKyInstance.post.mockRejectedValueOnce(err);
    const payload: InternalCreateAccountingJobPayload = {
      businessId: 'b1',
      periodStart: '2024-01-01T00:00:00Z',
      periodEnd: '2024-01-31T23:59:59Z',
    };

    await expect(svc.createAccountingJob(payload)).rejects.toBeInstanceOf(
      NotFoundException
    );
  });

  it('createAccountingJob - maps TimeoutError to ServiceUnavailableException', async () => {
    const timeoutErr = new Error('timeout');
    timeoutErr.name = 'TimeoutError';
    mockKyInstance.post.mockRejectedValueOnce(timeoutErr);

    const payload: InternalCreateAccountingJobPayload = {
      businessId: 'b1',
      periodStart: '2024-01-01T00:00:00Z',
      periodEnd: '2024-01-31T23:59:59Z',
    };

    await expect(svc.createAccountingJob(payload)).rejects.toBeInstanceOf(
      ServiceUnavailableException
    );
  });

  it('ensureEnabled - methods throw when API key missing', async () => {
    const cfgNoKey: Partial<ConfigService> = {
      get: (k: string, d?: unknown) => {
        if (k === 'AI_ACCOUNTANT_API_KEY') return '';
        if (k === 'AI_ACCOUNTANT_TIMEOUT_MS') return 1000;
        if (k === 'AI_ACCOUNTANT_URL') return 'http://localhost:8000';
        return d;
      },
    };

    const svcNoKey = new AccountantService(cfgNoKey as ConfigService);
    await expect(svcNoKey.healthCheck()).rejects.toBeInstanceOf(
      ServiceUnavailableException
    );
  });
});
