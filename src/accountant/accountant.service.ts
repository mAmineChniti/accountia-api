import {
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import ky, { HTTPError } from 'ky';
import type {
  CreateAccountingJobDto,
  InternalCreateAccountingJobPayload,
} from './dto';
import type {
  AccountingJobResponse,
  AccountingJobStatus,
  AccountingResults,
  BusinessJobsResponse,
  BusinessWorkResponse,
  TaxSummaryResponse,
  AccountingJobSummary,
} from './types';

@Injectable()
export class AccountantService {
  private readonly logger = new Logger(AccountantService.name);
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly httpClient: typeof ky;

  constructor(private configService: ConfigService) {
    this.baseUrl = this.configService.get<string>(
      'AI_ACCOUNTANT_URL',
      'http://localhost:8000'
    );
    this.apiKey = this.configService.get<string>('AI_ACCOUNTANT_API_KEY', '');
    this.timeoutMs = this.configService.get<number>(
      'AI_ACCOUNTANT_TIMEOUT_MS',
      30_000
    );

    if (!this.apiKey) {
      this.logger.warn(
        'AI_ACCOUNTANT_API_KEY not configured - accountant integration disabled'
      );
    }

    // Create ky instance with default config
    this.httpClient = ky.create({
      prefix: this.baseUrl,
      timeout: this.timeoutMs,
      headers: {
        'X-API-Key': this.apiKey,
      },
    });
  }

  /**
   * Ensure AI Accountant is enabled and configured
   */
  private ensureEnabled(): void {
    if (!this.apiKey) {
      throw new ServiceUnavailableException(
        'AI Accountant not configured - accountant integration disabled'
      );
    }
  }

  /**
   * Handle ky HTTP errors
   */
  private handleHttpError(error: unknown, operation: string): never {
    if (error instanceof HTTPError) {
      const cid = error.response.headers.get('x-correlation-id') ?? 'unknown';
      this.logger.error(
        `AI Accountant error: ${error.response.status} cid=${cid}`
      );
      throw new Error(`Failed to ${operation}`);
    }
    if (error instanceof Error && error.name === 'TimeoutError') {
      throw new ServiceUnavailableException(
        `AI Accountant request timed out after ${this.timeoutMs}ms`
      );
    }
    throw error;
  }

  /**
   * Create a new accounting job via AI Accountant service
   * Only accessible by account admins/managers
   */
  async createAccountingJob(
    dto: CreateAccountingJobDto | InternalCreateAccountingJobPayload
  ): Promise<AccountingJobResponse> {
    this.ensureEnabled();

    // debug logging removed

    try {
      const response = await this.httpClient.post('api/accounting/jobs', {
        json: dto,
      });
      const data = await response.json<AccountingJobResponse>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'create accounting job');
    }
  }

  /**
   * Get the status of an accounting job
   */
  async getJobStatus(
    taskId: string,
    businessId: string
  ): Promise<AccountingJobStatus> {
    this.ensureEnabled();

    // debug logging removed

    try {
      const response = await this.httpClient.get(
        `api/accounting/jobs/${encodeURIComponent(taskId)}`,
        {
          searchParams: {
            business_id: businessId,
          },
        }
      );
      const data = await response.json<AccountingJobStatus>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'get job status');
    }
  }

  /**
   * Get the results of a completed accounting job
   */
  async getJobResults(
    taskId: string,
    businessId: string
  ): Promise<AccountingResults> {
    this.ensureEnabled();

    // debug logging removed

    try {
      const response = await this.httpClient.get(
        `api/accounting/jobs/${encodeURIComponent(taskId)}/results`,
        {
          searchParams: {
            business_id: businessId,
          },
        }
      );
      const data = await response.json<AccountingResults>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'get job results');
    }
  }

  /**
   * Get all jobs for a business
   */
  async listBusinessJobs(
    businessId: string,
    status?: string,
    limit = 10
  ): Promise<BusinessJobsResponse> {
    this.ensureEnabled();

    const searchParams: Record<string, string> = {
      business_id: businessId,
      limit: limit.toString(),
    };
    if (status) {
      searchParams.status = status;
    }

    // debug logging removed

    try {
      const response = await this.httpClient.get('api/accounting/jobs', {
        searchParams,
      });
      const data = await response.json<BusinessJobsResponse>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'list jobs');
    }
  }

  /**
   * Get accounting history for a business
   */
  async getBusinessHistory(
    businessId: string,
    limit = 10
  ): Promise<{ business_id: string; tasks: AccountingJobSummary[] }> {
    this.ensureEnabled();

    // debug logging removed

    try {
      const response = await this.httpClient.get(
        `api/accounting/business/${encodeURIComponent(businessId)}/history`,
        {
          searchParams: { limit: limit.toString() },
        }
      );
      const data = await response.json<{
        business_id: string;
        tasks: AccountingJobSummary[];
      }>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'get history');
    }
  }

  /**
   * Get comprehensive work log for a business
   */
  async getBusinessWork(
    businessId: string,
    startDate?: string,
    endDate?: string,
    status?: string
  ): Promise<BusinessWorkResponse> {
    this.ensureEnabled();

    const searchParams: Record<string, string> = {
      ...(startDate && { start_date: startDate }),
      ...(endDate && { end_date: endDate }),
      ...(status && { status }),
    };
    // debug logging removed

    try {
      const response = await this.httpClient.get(
        `api/accounting/business/${encodeURIComponent(businessId)}/work`,
        {
          searchParams,
        }
      );
      const data = await response.json<BusinessWorkResponse>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'get work log');
    }
  }

  /**
   * Get Tunisian tax summary for a business
   */
  async getTaxSummary(
    businessId: string,
    year?: number
  ): Promise<TaxSummaryResponse> {
    this.ensureEnabled();

    // debug logging removed

    try {
      const response = await this.httpClient.get(
        `api/accounting/business/${encodeURIComponent(businessId)}/taxes`,
        {
          searchParams: year ? { year: year.toString() } : undefined,
        }
      );
      const data = await response.json<TaxSummaryResponse>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'get tax summary');
    }
  }

  /**
   * Cancel an accounting job
   */
  async cancelJob(
    taskId: string,
    businessId: string
  ): Promise<{
    task_id: string;
    status: string;
    message: string;
    previous_status: string;
  }> {
    this.ensureEnabled();

    // debug logging removed

    try {
      const response = await this.httpClient.delete(
        `api/accounting/jobs/${encodeURIComponent(taskId)}`,
        {
          searchParams: {
            business_id: businessId,
          },
        }
      );
      const data = await response.json<{
        task_id: string;
        status: string;
        message: string;
        previous_status: string;
      }>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'cancel accounting job');
    }
  }

  /**
   * Check if AI Accountant is available
   */
  async healthCheck(): Promise<boolean> {
    // Return false immediately if API key is not configured
    if (!this.apiKey) {
      this.logger.warn('AI Accountant health check: API key not configured');
      return false;
    }

    try {
      // Use shorter timeout for health check
      await this.httpClient.get('', { timeout: 5000 });
      return true;
    } catch (error) {
      this.logger.warn('AI Accountant health check failed', error);
      return false;
    }
  }
}
