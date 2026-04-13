import {
  Controller, Get, Post, Patch, Delete, Body, Param, Query, HttpCode, HttpStatus, UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiOkResponse, ApiCreatedResponse, ApiBearerAuth, ApiQuery, ApiParam } from '@nestjs/swagger';
import { VendorsService } from './vendors.service';
import { CreateVendorDto, UpdateVendorDto, VendorResponseDto, VendorListResponseDto } from './dto/vendor.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { BusinessRolesGuard, BusinessRoles } from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';

@ApiTags('Vendors')
@Controller('vendors')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
export class VendorsController {
  constructor(private readonly vendorsService: VendorsService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a vendor' })
  @ApiCreatedResponse({ type: VendorResponseDto })
  async create(@Body() dto: CreateVendorDto, @CurrentTenant() tenant: TenantContext): Promise<VendorResponseDto> {
    return this.vendorsService.create(tenant.businessId, tenant.databaseName, dto);
  }

  @Get()
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN, BusinessUserRole.MEMBER)
  @ApiOperation({ summary: 'List vendors' })
  @ApiOkResponse({ type: VendorListResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'search', required: false, type: String })
  async findAll(
    @CurrentTenant() tenant: TenantContext,
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('search') search?: string
  ): Promise<VendorListResponseDto> {
    return this.vendorsService.findByBusiness(tenant.businessId, tenant.databaseName, page, limit, search);
  }

  @Get(':id')
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN, BusinessUserRole.MEMBER)
  @ApiOperation({ summary: 'Get vendor by ID' })
  @ApiOkResponse({ type: VendorResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async findById(@Param('id') id: string, @CurrentTenant() tenant: TenantContext): Promise<VendorResponseDto> {
    return this.vendorsService.findById(id, tenant.businessId, tenant.databaseName);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a vendor' })
  @ApiOkResponse({ type: VendorResponseDto })
  @ApiParam({ name: 'id', type: String })
  async update(@Param('id') id: string, @Body() dto: UpdateVendorDto, @CurrentTenant() tenant: TenantContext): Promise<VendorResponseDto> {
    return this.vendorsService.update(id, tenant.businessId, tenant.databaseName, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a vendor' })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async delete(@Param('id') id: string, @CurrentTenant() tenant: TenantContext): Promise<void> {
    return this.vendorsService.delete(id, tenant.businessId, tenant.databaseName);
  }
}
