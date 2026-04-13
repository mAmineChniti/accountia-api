import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiOkResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { AnalyticsService } from './analytics.service';
import { AnalyticsQueryDto, AnalyticsDashboardDto } from './dto/analytics.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { BusinessRolesGuard, BusinessRoles } from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';

@ApiTags('Analytics')
@Controller('analytics')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN, BusinessUserRole.MEMBER)
export class AnalyticsController {
  constructor(private readonly analyticsService: AnalyticsService) {}

  @Get('dashboard')
  @ApiOperation({ summary: 'Get full analytics dashboard (revenue, AR aging, cash flow forecast)' })
  @ApiOkResponse({ type: AnalyticsDashboardDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiQuery({ name: 'startDate', required: false, type: String })
  @ApiQuery({ name: 'endDate', required: false, type: String })
  @ApiQuery({ name: 'groupBy', required: false, enum: ['monthly', 'weekly', 'yearly'] })
  async getDashboard(
    @CurrentTenant() tenant: TenantContext,
    @Query() query: AnalyticsQueryDto
  ): Promise<AnalyticsDashboardDto> {
    return this.analyticsService.getDashboard(
      tenant.businessId,
      tenant.databaseName,
      query
    );
  }
}
