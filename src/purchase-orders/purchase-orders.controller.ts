import {
  Controller, Get, Post, Patch, Delete, Body, Param, Query, HttpCode, HttpStatus, UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiOkResponse, ApiCreatedResponse, ApiBearerAuth, ApiQuery, ApiParam } from '@nestjs/swagger';
import { PurchaseOrdersService } from './purchase-orders.service';
import {
  CreatePurchaseOrderDto, UpdatePurchaseOrderDto, ReceiveGoodsDto, ApprovePODto,
  PurchaseOrderResponseDto, PurchaseOrderListResponseDto,
} from './dto/purchase-order.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { BusinessRolesGuard, BusinessRoles } from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';
import type { UserPayload } from '@/auth/types/auth.types';

@ApiTags('Purchase Orders')
@Controller('purchase-orders')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN, BusinessUserRole.MEMBER)
export class PurchaseOrdersController {
  constructor(private readonly purchaseOrdersService: PurchaseOrdersService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a purchase order' })
  @ApiCreatedResponse({ type: PurchaseOrderResponseDto })
  async create(@Body() dto: CreatePurchaseOrderDto, @CurrentTenant() tenant: TenantContext, @CurrentUser() user: UserPayload): Promise<PurchaseOrderResponseDto> {
    return this.purchaseOrdersService.create(tenant.businessId, tenant.databaseName, dto, user.id);
  }

  @Get()
  @ApiOperation({ summary: 'List purchase orders' })
  @ApiOkResponse({ type: PurchaseOrderListResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'status', required: false, type: String })
  async findAll(
    @CurrentTenant() tenant: TenantContext,
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('status') status?: string
  ): Promise<PurchaseOrderListResponseDto> {
    return this.purchaseOrdersService.findByBusiness(tenant.businessId, tenant.databaseName, page, limit, status);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get purchase order by ID' })
  @ApiOkResponse({ type: PurchaseOrderResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async findById(@Param('id') id: string, @CurrentTenant() tenant: TenantContext): Promise<PurchaseOrderResponseDto> {
    return this.purchaseOrdersService.findById(id, tenant.businessId, tenant.databaseName);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update draft purchase order' })
  @ApiOkResponse({ type: PurchaseOrderResponseDto })
  @ApiParam({ name: 'id', type: String })
  async update(@Param('id') id: string, @Body() dto: UpdatePurchaseOrderDto, @CurrentTenant() tenant: TenantContext): Promise<PurchaseOrderResponseDto> {
    return this.purchaseOrdersService.update(id, tenant.businessId, tenant.databaseName, dto);
  }

  @Patch(':id/submit')
  @ApiOperation({ summary: 'Submit PO for approval' })
  @ApiOkResponse({ type: PurchaseOrderResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async submit(@Param('id') id: string, @CurrentTenant() tenant: TenantContext): Promise<PurchaseOrderResponseDto> {
    return this.purchaseOrdersService.submit(id, tenant.businessId, tenant.databaseName);
  }

  @Patch(':id/approve')
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiOperation({ summary: 'Approve or reject a PO (Owner only)' })
  @ApiOkResponse({ type: PurchaseOrderResponseDto })
  @ApiParam({ name: 'id', type: String })
  async approve(@Param('id') id: string, @Body() dto: ApprovePODto, @CurrentTenant() tenant: TenantContext, @CurrentUser() user: UserPayload): Promise<PurchaseOrderResponseDto> {
    return this.purchaseOrdersService.approve(id, tenant.businessId, tenant.databaseName, dto, user.id);
  }

  @Patch(':id/receive')
  @ApiOperation({ summary: 'Record goods received (GRN)' })
  @ApiOkResponse({ type: PurchaseOrderResponseDto })
  @ApiParam({ name: 'id', type: String })
  async receiveGoods(@Param('id') id: string, @Body() dto: ReceiveGoodsDto, @CurrentTenant() tenant: TenantContext): Promise<PurchaseOrderResponseDto> {
    return this.purchaseOrdersService.receiveGoods(id, tenant.businessId, tenant.databaseName, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete draft purchase order' })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async delete(@Param('id') id: string, @CurrentTenant() tenant: TenantContext): Promise<void> {
    return this.purchaseOrdersService.delete(id, tenant.businessId, tenant.databaseName);
  }
}
