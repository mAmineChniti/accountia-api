import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiBearerAuth,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { RecurringInvoicesService } from './recurring-invoices.service';
import {
  CreateRecurringInvoiceDto,
  UpdateRecurringInvoiceDto,
  RecurringInvoiceResponseDto,
  RecurringInvoiceListResponseDto,
} from './dto/recurring-invoice.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { BusinessRolesGuard, BusinessRoles } from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';
import type { UserPayload } from '@/auth/types/auth.types';

@ApiTags('Recurring Invoices')
@Controller('recurring-invoices')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN, BusinessUserRole.MEMBER)
export class RecurringInvoicesController {
  constructor(private readonly recurringInvoicesService: RecurringInvoicesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a recurring invoice schedule' })
  @ApiCreatedResponse({ type: RecurringInvoiceResponseDto })
  async create(
    @Body() dto: CreateRecurringInvoiceDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<RecurringInvoiceResponseDto> {
    return this.recurringInvoicesService.create(
      tenant.businessId,
      tenant.databaseName,
      dto,
      user.id
    );
  }

  @Get()
  @ApiOperation({ summary: 'List all recurring invoice schedules' })
  @ApiOkResponse({ type: RecurringInvoiceListResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  async findAll(
    @CurrentTenant() tenant: TenantContext,
    @Query('page') page = 1,
    @Query('limit') limit = 10
  ): Promise<RecurringInvoiceListResponseDto> {
    return this.recurringInvoicesService.findByBusiness(
      tenant.businessId,
      tenant.databaseName,
      page,
      limit
    );
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a recurring invoice schedule by ID' })
  @ApiOkResponse({ type: RecurringInvoiceResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async findById(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<RecurringInvoiceResponseDto> {
    return this.recurringInvoicesService.findById(id, tenant.businessId, tenant.databaseName);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a recurring invoice schedule (pause, cancel, etc.)' })
  @ApiOkResponse({ type: RecurringInvoiceResponseDto })
  @ApiParam({ name: 'id', type: String })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateRecurringInvoiceDto,
    @CurrentTenant() tenant: TenantContext
  ): Promise<RecurringInvoiceResponseDto> {
    return this.recurringInvoicesService.update(id, tenant.businessId, tenant.databaseName, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a recurring invoice schedule' })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async delete(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<void> {
    return this.recurringInvoicesService.delete(id, tenant.businessId, tenant.databaseName);
  }
}
