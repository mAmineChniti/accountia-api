import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  HttpException,
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
  ApiResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { AccountantService } from './accountant.service';
import { CreateAccountingJobDto } from './dto';
import type { InternalCreateAccountingJobPayload } from './dto';
import type { TenantContext } from '@/common/tenant/tenant.types';
import type {
  AccountingJobResponse,
  AccountingJobStatus,
  AccountingJobSummary,
  AccountingResults,
  BusinessWorkResponse,
  TaxSummaryResponse,
} from './types';

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
    job: AccountingJobResponse;
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
    name: 'status',
    type: String,
    required: false,
    description: 'Filter by status (pending, processing, completed, failed)',
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
    @Query('status') status?: string,
    @Query('limit') limit?: string
  ): Promise<{
    message: string;
    timestamp: string;
    jobs: AccountingJobStatus[];
    total: number;
  }> {
    const result = await this.accountantService.listBusinessJobs(
      businessId || tenantCtx.businessId,
      status,
      limit
    );
    return {
      message: 'Accounting jobs retrieved successfully',
      timestamp: new Date().toISOString(),
      jobs: result.jobs,
      total: result.total,
    };
  }

  /**
   * Get status of a specific accounting job
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('jobs/:taskId')
  @ApiOperation({
    summary: 'Get job status',
    description: 'Check the processing status of an accounting job',
  })
  @ApiParam({
    name: 'taskId',
    type: String,
    description: 'Job task ID (format: {businessId}_{startDate}_{endDate})',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID (required as query parameter)',
  })
  @ApiOkResponse({
    description: 'Job status retrieved',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        job: { type: 'object' },
      },
    },
  })
  async getJobStatus(
    @Param('taskId') taskId: string,
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string
  ): Promise<{ message: string; timestamp: string; job: AccountingJobStatus }> {
    const jobStatus = await this.accountantService.getJobStatus(
      taskId,
      businessId || tenantCtx.businessId
    );
    return {
      message: 'Job status retrieved successfully',
      timestamp: new Date().toISOString(),
      job: jobStatus,
    };
  }

  /**
   * Get full results of a completed accounting job
   * Includes journal entries, tax calculations, reports
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('jobs/:taskId/results')
  @ApiOperation({
    summary: 'Get job results',
    description:
      'Retrieve complete accounting results including journal entries, tax calculations, financial reports, and AI insights',
  })
  @ApiParam({
    name: 'taskId',
    type: String,
    description: 'Job task ID',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID (required as query parameter)',
  })
  @ApiOkResponse({
    description: 'Job results retrieved',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        results: { type: 'object' },
      },
    },
  })
  async getJobResults(
    @Param('taskId') taskId: string,
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string
  ): Promise<{
    message: string;
    timestamp: string;
    results: AccountingResults;
  }> {
    const results = await this.accountantService.getJobResults(
      taskId,
      businessId || tenantCtx.businessId
    );
    return {
      message: 'Job results retrieved successfully',
      timestamp: new Date().toISOString(),
      results,
    };
  }

  /**
   * Cancel a pending or processing accounting job
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Delete('jobs/:taskId')
  @ApiOperation({
    summary: 'Cancel accounting job',
    description:
      'Cancel a pending or processing accounting job. Cannot cancel completed, failed, or already cancelled jobs.',
  })
  @ApiParam({
    name: 'taskId',
    type: String,
    description: 'Job task ID',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID (required as query parameter)',
  })
  @ApiOkResponse({
    description: 'Job cancelled successfully',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        result: {
          type: 'object',
          properties: {
            taskId: { type: 'string' },
            status: { type: 'string' },
            message: { type: 'string' },
            previousStatus: { type: 'string' },
          },
        },
      },
    },
  })
  async cancelJob(
    @Param('taskId') taskId: string,
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string
  ): Promise<{
    message: string;
    timestamp: string;
    result: {
      taskId: string;
      status: string;
      message: string;
      previousStatus: string;
    };
  }> {
    const result = await this.accountantService.cancelJob(
      taskId,
      businessId || tenantCtx.businessId
    );
    return {
      message: 'Job cancelled successfully',
      timestamp: new Date().toISOString(),
      result,
    };
  }

  /**
   * Get accounting history for the business
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('history')
  @ApiOperation({
    summary: 'Get accounting history',
    description: 'Get history of all accounting periods',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID (required as query parameter)',
  })
  @ApiQuery({
    name: 'limit',
    type: String,
    required: false,
    description: 'Maximum number of results (1-100, default: 10)',
  })
  @ApiOkResponse({
    description: 'Accounting history retrieved',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        businessId: { type: 'string' },
        tasks: { type: 'array' },
      },
    },
  })
  async getHistory(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('limit') limit?: string
  ): Promise<{
    message: string;
    timestamp: string;
    businessId: string;
    tasks: AccountingJobSummary[];
  }> {
    const history = await this.accountantService.getBusinessHistory(
      businessId || tenantCtx.businessId,
      limit
    );
    return {
      message: 'Accounting history retrieved successfully',
      timestamp: new Date().toISOString(),
      businessId: history.businessId,
      tasks: history.tasks,
    };
  }

  /**
   * Get comprehensive work log for the business
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('work')
  @ApiOperation({
    summary: 'Get work log',
    description: 'Get detailed work log with optional date/status filters',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID (required as query parameter)',
  })
  @ApiQuery({
    name: 'startDate',
    type: String,
    required: false,
    description: 'Filter from date (ISO 8601)',
  })
  @ApiQuery({
    name: 'endDate',
    type: String,
    required: false,
    description: 'Filter to date (ISO 8601)',
  })
  @ApiQuery({
    name: 'status',
    type: String,
    required: false,
    description: 'Filter by status (pending, processing, completed, failed)',
  })
  @ApiOkResponse({
    description: 'Work log retrieved',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        work: { type: 'object' },
      },
    },
  })
  async getWork(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('status') status?: string
  ): Promise<{
    message: string;
    timestamp: string;
    work: BusinessWorkResponse;
  }> {
    // Convert camelCase API params to snake_case for upstream service
    const work = await this.accountantService.getBusinessWork(
      businessId || tenantCtx.businessId,
      startDate,
      endDate,
      status
    );
    return {
      message: 'Work log retrieved successfully',
      timestamp: new Date().toISOString(),
      work,
    };
  }

  // Tax endpoints: GET /accountant/taxes and POST /accountant/taxes/calculate
  // Note: businessId is passed as a query parameter, not a path parameter

  /**
   * Get tax summary (accepts businessId as query param)
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('taxes')
  @ApiOperation({
    summary: 'Get tax summary',
    description:
      'Get persisted tax summary for a business (returns 404 if not found)',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID',
  })
  @ApiQuery({
    name: 'year',
    type: String,
    required: false,
    description: 'Tax year (defaults to current year)',
  })
  @ApiOkResponse({
    description: 'Tax summary retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        taxes: { type: 'object' },
      },
    },
  })
  async getTaxes(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('year') year?: string
  ): Promise<{
    message: string;
    timestamp: string;
    taxes: TaxSummaryResponse;
  }> {
    const id = businessId || tenantCtx.businessId;
    const taxes = await this.accountantService.getTaxSummary(id, year);
    return {
      message: 'Tax summary retrieved successfully',
      timestamp: new Date().toISOString(),
      taxes,
    };
  }

  /**
   * Calculate and persist tax summary for a given business and year (businessId as query param)
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Post('taxes/calculate')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Calculate and persist tax summary',
    description:
      'Calculate taxes for a year and persist the result in the tenant DB',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID',
  })
  @ApiQuery({
    name: 'year',
    type: String,
    required: false,
    description: 'Tax year (defaults to current year)',
  })
  @ApiCreatedResponse({
    description: 'Tax calculated and persisted successfully',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        result: { type: 'object' },
      },
    },
  })
  async calculateTaxes(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('year') year?: string
  ): Promise<{
    message: string;
    timestamp: string;
    result:
      | TaxSummaryResponse
      | { message: string; businessId: string; year: number };
  }> {
    const id = businessId || tenantCtx.businessId;
    const result = await this.accountantService.calculateTax(id, year);

    return {
      message: 'Tax calculation result',
      timestamp: new Date().toISOString(),
      result,
    };
  }

  /**
   * Health check - verify AI Accountant is available
   */
  @Get('health')
  @ApiOperation({
    summary: 'Health check',
    description: 'Check if AI Accountant service is available',
  })
  @ApiOkResponse({
    description: 'Health status - service available',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        status: { type: 'string' },
        service: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.SERVICE_UNAVAILABLE,
    description: 'Health status - service unavailable',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        timestamp: { type: 'string' },
        status: { type: 'string' },
        service: { type: 'string' },
      },
    },
  })
  async healthCheck(): Promise<{
    message: string;
    timestamp: string;
    status: 'available';
    service: string;
  }> {
    const isHealthy = await this.accountantService.healthCheck();

    if (!isHealthy) {
      throw new HttpException(
        {
          message: 'AI Accountant service is unavailable',
          timestamp: new Date().toISOString(),
          status: 'unavailable',
          service: 'ai-accountant',
        },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }

    return {
      message: 'AI Accountant service is available',
      timestamp: new Date().toISOString(),
      status: 'available',
      service: 'ai-accountant',
    };
  }
}
