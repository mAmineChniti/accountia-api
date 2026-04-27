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

    this.httpClient = ky.create({
      prefix: this.baseUrl,
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
            businessId: businessId,
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
    status?: string,
    limitInput?: string
  ): Promise<BusinessJobsResponse> {
    this.ensureEnabled();

    const limit = this.parsePositiveInt(limitInput, 10);
    const searchParams: Record<string, string> = {
      businessId: businessId,
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
    limitInput?: string
  ): Promise<{ businessId: string; tasks: AccountingJobSummary[] }> {
    this.ensureEnabled();

    const limit = this.parsePositiveInt(limitInput, 10);

    // debug logging removed

    try {
      const response = await this.httpClient.get(
        `api/accounting/business/${encodeURIComponent(businessId)}/history`,
        {
          searchParams: { limit: limit.toString() },
        }
      );
      const data = await response.json<{
        businessId: string;
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

    // Note: start_date and end_date are intentionally snake_case to match the upstream AI Accountant API contract
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
   * Parse and validate tax year with reasonable range bounds
   * @param value - Raw year string value
   * @param defaultValue - Default if value is undefined/empty
   * @returns Validated year number
   * @throws BadRequestException on invalid year
   */
  private parseTaxYear(
    value: string | undefined,
    defaultValue: number
  ): number {
    if (value === undefined || value === '') {
      return defaultValue;
    }
    const trimmed = value.trim();
    const parsed = Number.parseInt(trimmed, 10);
    if (Number.isNaN(parsed) || parsed.toString() !== trimmed) {
      throw new BadRequestException(`Invalid year value: ${value}`);
    }

    const currentYear = new Date().getFullYear();
    // Fixed lower bound allows historical data from year 2000; upper bound allows next tax year
    const minYear = 2000;
    const maxYear = currentYear + 1;

    if (parsed < minYear || parsed > maxYear) {
      throw new BadRequestException(
        `Year must be between ${minYear} and ${maxYear}, got: ${parsed}`
      );
    }
    return parsed;
  }

  /**
   * Parse and validate positive integer parameter
   * @param value - Raw string value
   * @param defaultValue - Default if value is undefined/empty
   * @param maxValue - Maximum allowed value (default: 100)
   * @returns Validated integer
   * @throws BadRequestException on invalid input
   */
  private parsePositiveInt(
    value: string | undefined,
    defaultValue: number,
    maxValue = 100
  ): number {
    if (value === undefined || value === '') {
      return defaultValue;
    }
    const trimmed = value.trim();
    const parsed = Number.parseInt(trimmed, 10);
    if (Number.isNaN(parsed) || parsed.toString() !== trimmed) {
      throw new BadRequestException(`Invalid integer value: ${value}`);
    }
    if (parsed < 1) {
      throw new BadRequestException(`Value must be at least 1, got: ${parsed}`);
    }
    if (parsed > maxValue) {
      throw new BadRequestException(
        `Value exceeds maximum of ${maxValue}, got: ${parsed}`
      );
    }
    return parsed;
  }

  /**
   * Get Tunisian tax summary for a business
   */
  async getTaxSummary(
    businessId: string,
    yearInput?: string
  ): Promise<TaxSummaryResponse> {
    this.ensureEnabled();

    const year = this.parseTaxYear(yearInput, new Date().getFullYear());

    try {
      const searchParams = { year: year.toString() };

      const response = await this.httpClient.get(
        `api/accounting/business/${encodeURIComponent(businessId)}/taxes`,
        {
          searchParams,
        }
      );
      const data = await response.json<TaxSummaryResponse>();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'get tax summary');
    }
  }

  /**
   * Calculate and persist tax summary for a business and year.
   * Calls POST /api/accounting/business/{businessId}/taxes/calculate
   */
  async calculateTax(
    businessId: string,
    yearInput?: string
  ): Promise<
    TaxSummaryResponse | { message: string; businessId: string; year: number }
  > {
    this.ensureEnabled();

    const year = this.parseTaxYear(yearInput, new Date().getFullYear());

    try {
      const searchParams = { year: year.toString() };

      const response = await this.httpClient.post(
        `api/accounting/business/${encodeURIComponent(businessId)}/taxes/calculate`,
        {
          searchParams,
        }
      );
      const data = await response.json<
        | TaxSummaryResponse
        | { message: string; businessId: string; year: number }
      >();
      return data;
    } catch (error) {
      this.handleHttpError(error, 'calculate tax summary');
    }
  }

  /**
   * Cancel an accounting job
   */
  async cancelJob(
    taskId: string,
    businessId: string
  ): Promise<{
    taskId: string;
    status: string;
    message: string;
    previousStatus: string;
  }> {
    this.ensureEnabled();

    // debug logging removed

    try {
      const response = await this.httpClient.delete(
        `api/accounting/jobs/${encodeURIComponent(taskId)}`,
        {
          searchParams: {
            businessId: businessId,
          },
        }
      );
      const data = await response.json<{
        taskId: string;
        status: string;
        message: string;
        previousStatus: string;
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
    try {
      // Call the service health endpoint (no API key required by the service)
      const response = await this.httpClient.get('api/health', {
        timeout: 5000,
      });
      const body: { status?: string } = await response.json();
      return !!(body && (body.status === 'healthy' || body.status === 'ready'));
    } catch (error) {
      this.logger.warn('AI Accountant health check failed', error);
      return false;
    }
  }
}
