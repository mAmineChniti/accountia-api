import {
  Controller,
  Get,
  Post,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiNotFoundResponse,
  ApiBadRequestResponse,
  ApiForbiddenResponse,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { CollectionsService } from './collections.service';
import {
  CollectionsDashboardDto,
  InvoiceRiskScoreDto,
  GenerateReminderResponseDto,
} from './dto/collections.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import {
  BusinessRolesGuard,
  BusinessRoles,
} from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import type { TenantContext } from '@/common/tenant/tenant.types';
import type { UserPayload } from '@/auth/types/auth.types';

@ApiTags('Collections')
@ApiBearerAuth()
@Controller('collections')
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
export class CollectionsController {
  constructor(private readonly collectionsService: CollectionsService) {}

  /**
   * GET /collections/dashboard
   * Full collections health view with risk scores + aggregate breakdown.
   */
  @Get('dashboard')
  @ApiOperation({
    summary: 'AI Collections dashboard with risk scores',
    description:
      'Returns risk scores (0–100) for all open invoices plus an aggregate breakdown by risk level. ' +
      'businessId is REQUIRED as a query parameter.',
  })
  @ApiOkResponse({
    description: 'Collections dashboard with risk scores',
    type: CollectionsDashboardDto,
  })
  @ApiForbiddenResponse({ description: 'Insufficient permissions' })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description: 'Business ID — required to resolve tenant context',
  })
  async getDashboard(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<CollectionsDashboardDto> {
    return this.collectionsService.getDashboard(
      tenant.businessId,
      tenant.databaseName,
      user.id
    );
  }

  /**
   * GET /collections/risk-scores
   * Lightweight list of scored invoices (no aggregate stats).
   */
  @Get('risk-scores')
  @ApiOperation({
    summary: 'AI late-payment risk scores for open invoices',
    description:
      'Scores every open invoice (ISSUED / VIEWED / PARTIAL / OVERDUE) with a risk index 0–100 ' +
      'based on days overdue, client payment history, and invoice amount. ' +
      'businessId is REQUIRED as a query parameter.',
  })
  @ApiOkResponse({
    description: 'Risk scores for all open invoices, sorted by risk descending',
    type: [InvoiceRiskScoreDto],
  })
  @ApiForbiddenResponse({ description: 'Insufficient permissions' })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description: 'Business ID — required to resolve tenant context',
  })
  async getRiskScores(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<InvoiceRiskScoreDto[]> {
    return this.collectionsService.getRiskScores(
      tenant.businessId,
      tenant.databaseName,
      user.id
    );
  }

  /**
   * POST /collections/invoices/:id/generate-reminder
   * Uses OpenRouter / Gemini to generate a personalised payment reminder.
   */
  @Post('invoices/:id/generate-reminder')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'AI-generate a personalised payment reminder',
    description:
      'Generates a ready-to-send French payment reminder email (subject + body) for an unpaid invoice. ' +
      'Tone adapts automatically based on risk level: gentle (LOW) → firm (MEDIUM/HIGH) → urgent + legal warning (CRITICAL). ' +
      'businessId is REQUIRED as a query parameter.',
  })
  @ApiOkResponse({
    description: 'AI-generated reminder message',
    type: GenerateReminderResponseDto,
  })
  @ApiNotFoundResponse({ description: 'Invoice not found' })
  @ApiBadRequestResponse({
    description:
      'Invoice is not in an open state (not ISSUED/VIEWED/PARTIAL/OVERDUE)',
  })
  @ApiForbiddenResponse({ description: 'Insufficient permissions' })
  @ApiParam({ name: 'id', description: 'Invoice ID', type: String })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description: 'Business ID — required to resolve tenant context',
  })
  async generateReminder(
    @Param('id') invoiceId: string,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<GenerateReminderResponseDto> {
    return this.collectionsService.generateReminder(
      invoiceId,
      tenant.businessId,
      tenant.databaseName,
      user.id
    );
  }
}
