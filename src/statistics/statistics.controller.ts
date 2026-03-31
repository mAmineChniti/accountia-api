import { Controller, Get, UseGuards, Query, Param, Res } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiOkResponse,
  ApiNotFoundResponse,
} from '@nestjs/swagger';
import { StatisticsService } from './statistics.service';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import type { Response } from 'express';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { Role } from '@/auth/enums/role.enum';
import { TransactionQueryDto } from './dto/transaction-query.dto';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import type { UserPayload } from '@/auth/types/auth.types';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';

@ApiTags('statistics')
@Controller('statistics')
export class StatisticsController {
  constructor(private readonly statisticsService: StatisticsService) {}

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_ADMIN, Role.PLATFORM_OWNER)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get Admin Statistics for Dashboard' })
  @ApiOkResponse({ description: 'Statistics retrieved successfully' })
  async getStatistics() {
    return this.statisticsService.getStatistics();
  }

  @Get('platform')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_ADMIN, Role.PLATFORM_OWNER)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get Platform Statistics (Users & Applications)' })
  @ApiOkResponse({ description: 'Platform statistics retrieved successfully' })
  async getPlatformStatistics(@Query('range') range?: string) {
    return this.statisticsService.getPlatformStatistics(range);
  }

  @Get('audit-logs')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_ADMIN, Role.PLATFORM_OWNER)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get Platform Audit Logs' })
  @ApiOkResponse({ description: 'Audit logs retrieved successfully' })
  async getAuditLogs(@Query('limit') limit?: number) {
    return this.statisticsService.getAuditLogs(limit);
  }

  @Get('transactions')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_ADMIN, Role.PLATFORM_OWNER, Role.BUSINESS_OWNER)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get Filtered Transactions for Reports' })
  @ApiOkResponse({ description: 'Transactions retrieved successfully' })
  async getFilteredTransactions(@Query() query: TransactionQueryDto) {
    return this.statisticsService.getFilteredTransactions(query);
  }

  @Get('transactions/:id/download')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_ADMIN, Role.PLATFORM_OWNER, Role.BUSINESS_OWNER)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Download transaction PDF' })
  @ApiOkResponse({ description: 'PDF file returned' })
  @ApiNotFoundResponse({ description: 'Transaction not found' })
  async download(@Param('id') id: string, @Res() res: Response) {
    try {
      const pdfBuffer = await this.statisticsService.generateTransactionPdf(id);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename=invoice-${id}.pdf`
      );
      res.send(pdfBuffer);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      res.status(404).json({ message });
    }
  }

  @Get('client-financials')
  @UseGuards(JwtAuthGuard, TenantContextGuard, RolesGuard)
  @Roles(Role.CLIENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get Client Dashboard Metrics' })
  @ApiOkResponse({ description: 'Client financials retrieved successfully' })
  async getClientFinancials(
    @CurrentUser() user: UserPayload,
    @CurrentTenant() tenant: TenantContext
  ) {
    return this.statisticsService.getClientFinancials(
      user.id,
      tenant.databaseName
    );
  }

  @Get('client-cash-flow')
  @UseGuards(JwtAuthGuard, TenantContextGuard, RolesGuard)
  @Roles(Role.CLIENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get Client Cash Flow Chart Data' })
  @ApiOkResponse({ description: 'Client cash flow retrieved successfully' })
  async getClientCashFlow(
    @CurrentUser() user: UserPayload,
    @CurrentTenant() tenant: TenantContext
  ) {
    return this.statisticsService.getClientCashFlow(
      user.id,
      tenant.databaseName
    );
  }
}
