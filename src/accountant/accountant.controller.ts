import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  BadRequestException,
  ServiceUnavailableException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiBadRequestResponse,
  ApiInternalServerErrorResponse,
  ApiBody,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { AccountantService } from './accountant.service';
import type { TenantContext } from '@/common/tenant/tenant.types';
import type {
  ServiceHealthResponse,
  AccountingResults,
  TaxResultsResponse,
  TaxPersistResponse,
  CreateJobResponse,
  JobSummary,
  JobsListResponse,
} from './types/accountant-response';
import {
  CreateAccountingJobDto,
  InternalCreateAccountingJobPayload,
} from './dto/create-job.dto';

/**
 * Accountant Controller
 *
 * Routes all accounting requests to the AI Accountant service.
 * Security: Frontend can ONLY access through this API - never directly to AI Accountant
 * The AI Accountant service requires an API key that only this backend has.
 */
@ApiTags('Accountant')
@ApiBearerAuth()
@Controller('accountant')
export class AccountantController {
  constructor(private readonly accountantService: AccountantService) {}

  /**
   * Create a new AI accounting job
   * Generates journal entries, tax calculations, and financial reports
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Post('jobs')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create AI accounting job',
    description:
      'Start AI-powered accounting for a date range. The AI will generate journal entries, calculate taxes, and produce financial reports.',
  })
  @ApiBody({
    type: CreateAccountingJobDto,
    description: 'Create accounting job request',
  })
  @ApiCreatedResponse({
    description: 'Accounting job created successfully',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        job: {
          type: 'object',
          properties: {
            taskId: { type: 'string' },
            status: { type: 'string' },
            message: { type: 'string' },
            estimatedCompletion: { type: 'string' },
          },
        },
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Invalid period range or missing required fields',
  })
  @ApiInternalServerErrorResponse({
    description: 'AI Accountant service error',
  })
  async createJob(
    @Body() dto: CreateAccountingJobDto,
    @CurrentTenant() tenantCtx: TenantContext
  ): Promise<{
    message: string;
    timestamp: string;
    job: CreateJobResponse;
  }> {
    const businessId = dto.businessId ?? tenantCtx.businessId;
    const payload: InternalCreateAccountingJobPayload = {
      periodStart: dto.periodStart.toISOString(),
      periodEnd: dto.periodEnd.toISOString(),
      businessId,
    };
    const job = await this.accountantService.createAccountingJob(payload);

    return {
      message: 'Accounting job created. Processing will begin shortly.',
      timestamp: new Date().toISOString(),
      job,
    };
  }

  /**
   * List all accounting jobs for the current business
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('jobs')
  @ApiOperation({
    summary: 'List accounting jobs',
    description: 'Get all AI accounting jobs for the current business',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID (required as query parameter for GET requests)',
  })
  @ApiQuery({
    name: 'limit',
    type: String,
    required: false,
    description: 'Maximum number of results (1-100, default: 10)',
  })
  @ApiOkResponse({
    description: 'List of accounting jobs',
    schema: {
      type: 'object',
      properties: {
        jobs: { type: 'array' },
        total: { type: 'number' },
      },
    },
  })
  async listJobs(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('limit') limit?: string
  ): Promise<{
    message: string;
    timestamp: string;
    jobs: JobSummary[];
    total: number;
  }> {
    const result: JobsListResponse =
      await this.accountantService.listBusinessJobs(
        businessId || tenantCtx.businessId,
        limit
      );
    return {
      message: 'Accounting jobs retrieved successfully',
      timestamp: new Date().toISOString(),
      jobs: result.jobs,
      total: result.jobs ? result.jobs.length : 0,
    };
  }

  /**
   * Get job status or results
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('jobs/:taskId')
  @ApiOperation({
    summary: 'Get job status or results',
    description:
      'Returns job status while processing and full results when the job is completed',
  })
  @ApiOkResponse({ description: 'Job status or full results' })
  @ApiParam({
    name: 'taskId',
    type: String,
    description: 'Job task ID (format: {businessId}_{startDate}_{endDate})',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: false,
    description:
      'Business ID (query param; falls back to tenant businessId when omitted)',
  })
  async getJobResults(
    @Param('taskId') taskId: string,
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId?: string
  ): Promise<{
    message: string;
    timestamp: string;
    results: AccountingResults;
  }> {
    const id = businessId ?? tenantCtx.businessId;
    const results = await this.accountantService.getJobResults(taskId, id);

    return {
      message: 'Job results retrieved successfully',
      timestamp: new Date().toISOString(),
      results,
    };
  }

  /**
   * Get tax summary for a business and year
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('taxes/:year')
  @ApiOperation({ summary: 'Get tax summary by business and year' })
  @ApiParam({ name: 'year', type: Number })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: false,
    description:
      'Business ID (query param; falls back to tenant businessId when omitted)',
  })
  @ApiOkResponse({ description: 'Tax summary retrieved' })
  async getTaxesByYear(
    @CurrentTenant() tenantCtx: TenantContext,
    @Param('year') year: string,
    @Query('businessId') businessId?: string
  ): Promise<TaxResultsResponse> {
    const parsedYear = Number(year);
    if (
      !Number.isInteger(parsedYear) ||
      Number.isNaN(parsedYear) ||
      parsedYear < 2000 ||
      parsedYear > 2100
    ) {
      throw new BadRequestException(
        'Year must be a valid integer between 2000 and 2100'
      );
    }
    const id = businessId ?? tenantCtx.businessId;
    return this.accountantService.getTaxResults(id, parsedYear);
  }

  /**
   * Calculate and persist tax summary for a business and year
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Post('taxes/:year')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Calculate and persist tax summary' })
  @ApiParam({ name: 'year', type: Number })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: false,
    description:
      'Business ID (query param; falls back to tenant businessId when omitted)',
  })
  @ApiCreatedResponse({ description: 'Tax calculation initiated/persisted' })
  async calculateTaxesByYear(
    @CurrentTenant() tenantCtx: TenantContext,
    @Param('year') year: string,
    @Query('businessId') businessId?: string
  ): Promise<TaxPersistResponse> {
    const parsedYear = Number(year);
    if (
      !Number.isInteger(parsedYear) ||
      Number.isNaN(parsedYear) ||
      parsedYear < 2000 ||
      parsedYear > 2100
    ) {
      throw new BadRequestException(
        'Year must be a valid integer between 2000 and 2100'
      );
    }
    const id = businessId ?? tenantCtx.businessId;
    return this.accountantService.calculateTaxes(id, parsedYear);
  }

  /**
   * Get AI Accountant service health
   */
  @UseGuards(JwtAuthGuard)
  @Get('health')
  @ApiOperation({
    summary: 'AI Accountant health',
    description:
      'Get service health and version information from AI Accountant',
  })
  @ApiOkResponse({
    description: 'AI Accountant health status',
    schema: {
      type: 'object',
      properties: {
        service: { type: 'string' },
        status: { type: 'string' },
        timestamp: { type: 'string' },
      },
    },
  })
  async health(): Promise<{
    service: string;
    status: string;
    timestamp?: string;
    details?: ServiceHealthResponse;
  }> {
    try {
      const data = await this.accountantService.healthCheck();
      return {
        service: 'ai-accountant',
        status: data.status === 'ready' ? 'available' : data.status,
        timestamp: data.timestamp,
        details: data,
      };
    } catch (error) {
      throw new ServiceUnavailableException({
        service: 'ai-accountant',
        message: (error as Error).message ?? 'AI Accountant unavailable',
      });
    }
  }
}
