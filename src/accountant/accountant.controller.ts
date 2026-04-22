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
  BadRequestException,
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
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { AccountantService } from './accountant.service';
import { CreateAccountingJobDto } from './dto';
import type { InternalCreateAccountingJobPayload } from './dto';
import type { TenantContext } from '@/common/tenant/tenant.types';

/**
 * Parse and validate positive integer query parameter
 * @param value - Raw query string value
 * @param defaultValue - Default if value is undefined/empty
 * @param maxValue - Maximum allowed value (default: 100)
 * @returns Validated integer
 * @throws BadRequestException on invalid input
 */
function parsePositiveInt(
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
        success: { type: 'boolean' },
        data: {
          type: 'object',
          properties: {
            task_id: { type: 'string' },
            status: { type: 'string' },
            message: { type: 'string' },
            estimated_completion: { type: 'string' },
          },
        },
        message: { type: 'string' },
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
  ) {
    const businessId = dto.businessId ?? tenantCtx.businessId;
    const payload: InternalCreateAccountingJobPayload = {
      period_start: dto.periodStart.toISOString(),
      period_end: dto.periodEnd.toISOString(),
      business_id: businessId,
    };
    const job = await this.accountantService.createAccountingJob(payload);

    return {
      success: true,
      data: job,
      message: 'Accounting job created. Processing will begin shortly.',
    };
  }

  @UseGuards(JwtAuthGuard, TenantContextGuard)

  /**
   * List all accounting jobs for the current business
   */
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
        success: { type: 'boolean' },
        data: { type: 'array' },
        meta: {
          type: 'object',
          properties: {
            total: { type: 'number' },
          },
        },
      },
    },
  })
  async listJobs(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('status') status?: string,
    @Query('limit') limit?: string
  ) {
    const result = await this.accountantService.listBusinessJobs(
      businessId || tenantCtx.businessId,
      status,
      parsePositiveInt(limit, 10)
    );

    return {
      success: true,
      data: result.jobs,
      meta: { total: result.total },
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
        success: { type: 'boolean' },
        data: { type: 'object' },
      },
    },
  })
  async getJobStatus(
    @Param('taskId') taskId: string,
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string
  ) {
    const jobStatus = await this.accountantService.getJobStatus(
      taskId,
      businessId || tenantCtx.businessId
    );

    return {
      success: true,
      data: jobStatus,
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
        success: { type: 'boolean' },
        data: { type: 'object' },
      },
    },
  })
  async getJobResults(
    @Param('taskId') taskId: string,
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string
  ) {
    const results = await this.accountantService.getJobResults(
      taskId,
      businessId || tenantCtx.businessId
    );

    return {
      success: true,
      data: results,
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
        success: { type: 'boolean' },
        data: {
          type: 'object',
          properties: {
            task_id: { type: 'string' },
            status: { type: 'string' },
            message: { type: 'string' },
            previous_status: { type: 'string' },
          },
        },
      },
    },
  })
  async cancelJob(
    @Param('taskId') taskId: string,
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string
  ) {
    const result = await this.accountantService.cancelJob(
      taskId,
      businessId || tenantCtx.businessId
    );

    return {
      success: true,
      data: result,
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
        success: { type: 'boolean' },
        data: { type: 'object' },
      },
    },
  })
  async getHistory(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('limit') limit?: string
  ) {
    const history = await this.accountantService.getBusinessHistory(
      businessId || tenantCtx.businessId,
      parsePositiveInt(limit, 10)
    );

    return {
      success: true,
      data: history,
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
    name: 'start_date',
    type: String,
    required: false,
    description: 'Filter from date (ISO 8601)',
  })
  @ApiQuery({
    name: 'end_date',
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
        success: { type: 'boolean' },
        data: { type: 'object' },
      },
    },
  })
  async getWork(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('start_date') startDate?: string,
    @Query('end_date') endDate?: string,
    @Query('status') status?: string
  ) {
    const work = await this.accountantService.getBusinessWork(
      businessId || tenantCtx.businessId,
      startDate,
      endDate,
      status
    );

    return {
      success: true,
      data: work,
    };
  }

  /**
   * Get Tunisian tax summary for the business
   */
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Get('taxes')
  @ApiOperation({
    summary: 'Get tax summary',
    description:
      'Calculate taxes per Tunisian tax law (VAT, corporate tax, withholding)',
  })
  @ApiQuery({
    name: 'businessId',
    type: String,
    required: true,
    description: 'Business ID (required as query parameter)',
  })
  @ApiQuery({
    name: 'year',
    type: String,
    required: false,
    description: 'Tax year (e.g., 2024). Defaults to current year.',
  })
  @ApiOkResponse({
    description: 'Tax summary retrieved',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean' },
        data: { type: 'object' },
      },
    },
  })
  async getTaxes(
    @CurrentTenant() tenantCtx: TenantContext,
    @Query('businessId') businessId: string,
    @Query('year') year?: string
  ) {
    const taxes = await this.accountantService.getTaxSummary(
      businessId || tenantCtx.businessId,
      parsePositiveInt(year, new Date().getFullYear(), new Date().getFullYear())
    );

    return {
      success: true,
      data: taxes,
    };
  }

  /**
   * Health check - verify AI Accountant is available
   */
  @Get('health')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Health check',
    description: 'Check if AI Accountant service is available',
  })
  @ApiOkResponse({
    description: 'Health status',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean' },
        service: { type: 'string' },
        status: { type: 'string' },
      },
    },
  })
  async healthCheck() {
    const isHealthy = await this.accountantService.healthCheck();

    return {
      success: isHealthy,
      service: 'ai-accountant',
      status: isHealthy ? 'available' : 'unavailable',
    };
  }
}
