import {
  Injectable,
  Logger,
  ServiceUnavailableException,
  BadRequestException,
  BadGatewayException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import ky, { HTTPError, type KyInstance } from 'ky';
import type { InternalCreateAccountingJobPayload } from './dto/create-job.dto';
import {
  AccountingResults,
  CreateJobResponse,
  JobsListResponse,
  ServiceHealthResponse,
  TaxPersistResponse,
  TaxResultsResponse,
} from './types/accountant-response';

@Injectable()
export class AccountantService {
  private readonly logger = new Logger(AccountantService.name);
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly httpClient: KyInstance;

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
    const headers = this.apiKey ? { 'X-API-Key': this.apiKey } : undefined;

    const normalizedPrefix = this.baseUrl.replace(/\/+$/, '') + '/';

    this.httpClient = ky.create({
      prefix: normalizedPrefix,
      timeout: this.timeoutMs,
      headers,
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
      const status = error.response.status;
      const cid = error.response.headers.get('x-correlation-id') ?? 'unknown';
      this.logger.error(
        `AI Accountant error: ${status} cid=${cid} during ${operation}`
      );

      // Map common upstream HTTP errors to Nest exceptions
      if (status === 400)
        throw new BadRequestException(
          `AI Accountant: bad request when trying to ${operation}`
        );
      if (status === 401)
        throw new BadGatewayException(
          `AI Accountant: upstream returned 401 (unauthorized) when trying to ${operation}`
        );
      if (status === 403)
        throw new BadGatewayException(
          `AI Accountant: upstream returned 403 (forbidden) when trying to ${operation}`
        );
      if (status === 404)
        throw new NotFoundException(
          `AI Accountant: resource not found when trying to ${operation}`
        );
      // 5xx -> service unavailable / internal
      if (status >= 500)
        throw new ServiceUnavailableException(
          `AI Accountant service error (${status}) when trying to ${operation}`
        );

      throw new InternalServerErrorException(
        `AI Accountant error (${status}) when trying to ${operation}`
      );
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
    dto: InternalCreateAccountingJobPayload
  ): Promise<CreateJobResponse> {
    this.ensureEnabled();

    // debug logging removed

    try {
      const response = await this.httpClient.post('api/accounting/jobs', {
        json: dto,
      });
      const data = await response.json<CreateJobResponse>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'create accounting job');
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

    try {
      // The upstream API exposes a single GET /api/accounting/jobs/{task_id}
      // which returns status while processing and full results when completed.
      const response = await this.httpClient.get(
        `api/accounting/jobs/${encodeURIComponent(taskId)}`,
        {
          searchParams: {
            businessId: businessId,
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
    limitInput?: string
  ): Promise<JobsListResponse> {
    this.ensureEnabled();

    const searchParams: Record<string, string> = {
      businessId: businessId,
      limit: limitInput ?? '10', // default limit
    };

    try {
      const response = await this.httpClient.get('api/accounting/jobs', {
        searchParams,
      });
      const data = await response.json<JobsListResponse>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'list jobs');
    }
  }

  async calculateTaxes(
    businessId: string,
    year: number
  ): Promise<TaxPersistResponse> {
    this.ensureEnabled();

    try {
      const path = `api/accounting/taxes/${encodeURIComponent(
        businessId
      )}/${encodeURIComponent(year)}`;
      this.logger.debug(`AI Accountant POST ${path}`);
      const response = await this.httpClient.post(path);
      const data = await response.json<TaxPersistResponse>();
      return data;
    } catch (error) {
      if (error instanceof HTTPError) {
        try {
          const text = await error.response.text();
          this.logger.debug(
            `AI Accountant response body on error: ${text.slice(0, 200)}`
          );
        } catch {
          this.logger.debug('Failed to read upstream error body');
        }
      }
      this.handleHttpError(error, 'calculate taxes');
    }
  }
  async getTaxResults(
    businessId: string,
    year: number
  ): Promise<TaxResultsResponse> {
    this.ensureEnabled();

    try {
      const path = `api/accounting/taxes/${encodeURIComponent(
        businessId
      )}/${encodeURIComponent(year)}`;
      this.logger.debug(`AI Accountant GET ${path}`);
      const response = await this.httpClient.get(path);
      const data = await response.json<TaxResultsResponse>();
      return data;
    } catch (error) {
      if (error instanceof HTTPError) {
        try {
          const text = await error.response.text();
          this.logger.debug(
            `AI Accountant response body on error: ${text.slice(0, 200)}`
          );
        } catch {
          this.logger.debug('Failed to read upstream error body');
        }
      }
      this.handleHttpError(error, 'get tax results');
    }
  }

  async healthCheck(): Promise<ServiceHealthResponse> {
    this.ensureEnabled();

    try {
      const response = await this.httpClient.get('api/health');
      const data = await response.json<ServiceHealthResponse>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'health check');
    }
  }
}
