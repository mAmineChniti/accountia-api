import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiOkResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { ReportsService } from './reports.service';
import {
  VatReportQueryDto,
  VatReportPeriod,
  VatReportResponseDto,
} from './dto/vat-report.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import {
  BusinessRolesGuard,
  BusinessRoles,
} from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';

@ApiTags('Reports')
@Controller('reports')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(
  BusinessUserRole.OWNER,
  BusinessUserRole.ADMIN,
  BusinessUserRole.MEMBER
)
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Get('vat')
  @ApiOperation({
    summary: 'Get VAT compliance report',
    description:
      'Generate a VAT report for the specified period. businessId required as query param.',
  })
  @ApiOkResponse({
    description: 'VAT report generated',
    type: VatReportResponseDto,
  })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiQuery({ name: 'period', required: true, enum: VatReportPeriod })
  @ApiQuery({ name: 'year', required: false, type: String })
  @ApiQuery({ name: 'month', required: false, type: String })
  @ApiQuery({ name: 'quarter', required: false, type: String })
  @ApiQuery({ name: 'startDate', required: false, type: String })
  @ApiQuery({ name: 'endDate', required: false, type: String })
  async getVatReport(
    @CurrentTenant() tenant: TenantContext,
    @Query() query: VatReportQueryDto
  ): Promise<VatReportResponseDto> {
    return this.reportsService.getVatReport(
      tenant.businessId,
      tenant.databaseName,
      query
    );
  }
}
