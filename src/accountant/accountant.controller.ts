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
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiBadRequestResponse,
  ApiInternalServerErrorResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { AccountantService } from './accountant.service';
import type {
  CreateAccountingJobDto,
  InternalCreateAccountingJobPayload,
} from './dto';
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
@UseGuards(JwtAuthGuard, TenantContextGuard)
export class AccountantController {
  constructor(private readonly accountantService: AccountantService) {}

  /**
   * Create a new AI accounting job
   * Generates journal entries, tax calculations, and financial reports
   */
  @Post('jobs')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create AI accounting job',
    description:
      'Start AI-powered accounting for a date range. The AI will generate journal entries, calculate taxes, and produce financial reports.',
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
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Invalid period range' })
  @ApiInternalServerErrorResponse({
    description: 'AI Accountant service error',
  })
  async createJob(
    @Body() dto: CreateAccountingJobDto,
    @CurrentTenant() tenantCtx: TenantContext
  ) {
    const payload: InternalCreateAccountingJobPayload = {
      period_start: dto.period_start,
      period_end: dto.period_end,
      business_id: tenantCtx.businessId,
    };
    const job = await this.accountantService.createAccountingJob(payload);

    return {
      success: true,
      data: job,
      message: 'Accounting job created. Processing will begin shortly.',
    };
  }

  /**
   * List all accounting jobs for the current business
   */
  @Get('jobs')
  @ApiOperation({
    summary: 'List accounting jobs',
    description: 'Get all AI accounting jobs for the current business',
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
    @Query('status') status?: string,
    @Query('limit') limit?: string
  ) {
    const result = await this.accountantService.listBusinessJobs(
      tenantCtx.businessId,
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
  @Get('jobs/:taskId')
  @ApiOperation({
    summary: 'Get job status',
    description: 'Check the processing status of an accounting job',
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
    @CurrentTenant() tenantCtx: TenantContext
  ) {
    const jobStatus = await this.accountantService.getJobStatus(
      taskId,
      tenantCtx.businessId
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
  @Get('jobs/:taskId/results')
  @ApiOperation({
    summary: 'Get job results',
    description:
      'Retrieve complete accounting results including journal entries, tax calculations, financial reports, and AI insights',
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
    @CurrentTenant() tenantCtx: TenantContext
  ) {
    const results = await this.accountantService.getJobResults(
      taskId,
      tenantCtx.businessId
    );

    return {
      success: true,
      data: results,
    };
  }

  /**
   * Get accounting history for the business
   */
  @Get('history')
  @ApiOperation({
    summary: 'Get accounting history',
    description: 'Get history of all accounting periods',
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
    @Query('limit') limit?: string
  ) {
    const history = await this.accountantService.getBusinessHistory(
      tenantCtx.businessId,
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
  @Get('work')
  @ApiOperation({
    summary: 'Get work log',
    description: 'Get detailed work log with optional date/status filters',
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
    @Query('start_date') startDate?: string,
    @Query('end_date') endDate?: string,
    @Query('status') status?: string
  ) {
    const work = await this.accountantService.getBusinessWork(
      tenantCtx.businessId,
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
  @Get('taxes')
  @ApiOperation({
    summary: 'Get tax summary',
    description:
      'Calculate taxes per Tunisian tax law (VAT, corporate tax, withholding)',
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
    @Query('year') year?: string
  ) {
    const taxes = await this.accountantService.getTaxSummary(
      tenantCtx.businessId,
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
