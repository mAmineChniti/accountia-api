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
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { type Multer } from 'multer';
import {
  ApiTags,
  ApiOperation,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiNotFoundResponse,
  ApiBadRequestResponse,
  ApiForbiddenResponse,
  ApiParam,
  ApiQuery,
  ApiBearerAuth,
  ApiConsumes,
} from '@nestjs/swagger';
import { InvoicesService } from './invoices.service';
import {
  CreatePersonalInvoiceDto,
  CreateCompanyInvoiceDto,
  UpdateInvoiceDto,
  PersonalInvoiceResponseDto,
  CompanyInvoiceResponseDto,
  InvoiceListResponseDto,
} from '@/invoices/dto/invoice.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import {
  BusinessRolesGuard,
  BusinessRoles,
} from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { parseFile } from '@/common/utils/file-parser.util';
import type { TenantContext } from '@/common/tenant/tenant.types';

@ApiTags('Invoices')
@Controller('invoices')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
export class InvoicesController {
  constructor(private readonly invoicesService: InvoicesService) {}

  // Personal Invoices Endpoints
  @Post('personal')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a personal invoice',
    description: 'Issue a personal invoice to an individual',
  })
  @ApiCreatedResponse({
    description: 'Personal invoice created successfully',
    type: PersonalInvoiceResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Invalid input data or insufficient product quantity',
  })
  @ApiForbiddenResponse({
    description:
      'Insufficient permissions or product does not belong to business',
  })
  async createPersonalInvoice(
    @Body() createInvoiceDto: CreatePersonalInvoiceDto,
    @CurrentTenant() tenant: TenantContext
  ): Promise<PersonalInvoiceResponseDto> {
    return this.invoicesService.createPersonalInvoice(
      tenant.businessId,
      createInvoiceDto
    );
  }

  @Get('personal/business')
  @ApiOperation({
    summary: 'Get all personal invoices issued by business',
    description:
      'Retrieve paginated list of personal invoices issued by the current business',
  })
  @ApiOkResponse({
    description: 'Personal invoices retrieved successfully',
    type: InvoiceListResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default: 1)',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page (default: 10)',
  })
  async getPersonalInvoicesByBusiness(
    @CurrentTenant() tenant: TenantContext,
    @Query('page') page = 1,
    @Query('limit') limit = 10
  ): Promise<InvoiceListResponseDto> {
    return this.invoicesService.getPersonalInvoicesByBusiness(
      tenant.businessId,
      page,
      limit
    );
  }

  @Get('personal/:id')
  @ApiOperation({
    summary: 'Get a personal invoice by ID',
  })
  @ApiOkResponse({
    description: 'Personal invoice retrieved successfully',
    type: PersonalInvoiceResponseDto,
  })
  @ApiNotFoundResponse({ description: 'Personal invoice not found' })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async getPersonalInvoiceById(
    @Param('id') id: string
  ): Promise<PersonalInvoiceResponseDto> {
    return this.invoicesService.getPersonalInvoiceById(id);
  }

  @Patch('personal/:id')
  @ApiOperation({
    summary: 'Update a personal invoice',
    description: 'Update invoice details (e.g., mark as paid)',
  })
  @ApiOkResponse({
    description: 'Personal invoice updated successfully',
    type: PersonalInvoiceResponseDto,
  })
  @ApiNotFoundResponse({ description: 'Personal invoice not found' })
  @ApiForbiddenResponse({
    description: 'Invoice does not belong to your business',
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async updatePersonalInvoice(
    @Param('id') id: string,
    @Body() updateInvoiceDto: UpdateInvoiceDto,
    @CurrentTenant() tenant: TenantContext
  ): Promise<PersonalInvoiceResponseDto> {
    return this.invoicesService.updatePersonalInvoice(
      id,
      tenant.businessId,
      updateInvoiceDto
    );
  }

  @Delete('personal/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a personal invoice',
  })
  @ApiNotFoundResponse({ description: 'Personal invoice not found' })
  @ApiForbiddenResponse({
    description: 'Invoice does not belong to your business',
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async deletePersonalInvoice(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<void> {
    return this.invoicesService.deletePersonalInvoice(id, tenant.businessId);
  }

  // Company Invoices Endpoints
  @Post('company')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a company invoice',
    description: 'Issue a company invoice to another business',
  })
  @ApiCreatedResponse({
    description: 'Company invoice created successfully',
    type: CompanyInvoiceResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Invalid input data or insufficient product quantity',
  })
  @ApiForbiddenResponse({
    description:
      'Insufficient permissions or product does not belong to business',
  })
  async createCompanyInvoice(
    @Body() createInvoiceDto: CreateCompanyInvoiceDto,
    @CurrentTenant() tenant: TenantContext
  ): Promise<CompanyInvoiceResponseDto> {
    return this.invoicesService.createCompanyInvoice(
      tenant.businessId,
      createInvoiceDto
    );
  }

  @Get('company/business')
  @ApiOperation({
    summary: 'Get all company invoices issued by business',
    description:
      'Retrieve paginated list of company invoices issued by the current business',
  })
  @ApiOkResponse({
    description: 'Company invoices retrieved successfully',
    type: InvoiceListResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default: 1)',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page (default: 10)',
  })
  async getCompanyInvoicesByBusiness(
    @CurrentTenant() tenant: TenantContext,
    @Query('page') page = 1,
    @Query('limit') limit = 10
  ): Promise<InvoiceListResponseDto> {
    return this.invoicesService.getCompanyInvoicesByBusiness(
      tenant.businessId,
      page,
      limit
    );
  }

  @Get('company/:id')
  @ApiOperation({
    summary: 'Get a company invoice by ID',
  })
  @ApiOkResponse({
    description: 'Company invoice retrieved successfully',
    type: CompanyInvoiceResponseDto,
  })
  @ApiNotFoundResponse({ description: 'Company invoice not found' })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async getCompanyInvoiceById(
    @Param('id') id: string
  ): Promise<CompanyInvoiceResponseDto> {
    return this.invoicesService.getCompanyInvoiceById(id);
  }

  @Patch('company/:id')
  @ApiOperation({
    summary: 'Update a company invoice',
    description: 'Update invoice details (e.g., mark as paid)',
  })
  @ApiOkResponse({
    description: 'Company invoice updated successfully',
    type: CompanyInvoiceResponseDto,
  })
  @ApiNotFoundResponse({ description: 'Company invoice not found' })
  @ApiForbiddenResponse({
    description: 'Invoice does not belong to your business',
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async updateCompanyInvoice(
    @Param('id') id: string,
    @Body() updateInvoiceDto: UpdateInvoiceDto,
    @CurrentTenant() tenant: TenantContext
  ): Promise<CompanyInvoiceResponseDto> {
    return this.invoicesService.updateCompanyInvoice(
      id,
      tenant.businessId,
      updateInvoiceDto
    );
  }

  @Delete('company/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a company invoice',
  })
  @ApiNotFoundResponse({ description: 'Company invoice not found' })
  @ApiForbiddenResponse({
    description: 'Invoice does not belong to your business',
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async deleteCompanyInvoice(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<void> {
    return this.invoicesService.deleteCompanyInvoice(id, tenant.businessId);
  }

  @Post('personal/import')
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(FileInterceptor('file'))
  @ApiConsumes('multipart/form-data')
  @ApiOperation({
    summary: 'Import personal invoices from CSV or Excel',
    description:
      'Bulk import personal invoices from a CSV or Excel file. Required columns: clientUserId, productId, quantity',
  })
  @ApiCreatedResponse({
    description: 'Personal invoices imported successfully',
    schema: {
      type: 'object',
      properties: {
        imported: { type: 'number' },
        failed: { type: 'number' },
        errors: { type: 'array', items: { type: 'string' } },
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Invalid file format or data' })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  async importPersonalInvoices(
    @UploadedFile() file: Multer.File,
    @CurrentTenant() tenant: TenantContext
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    const records = await parseFile(
      (file as unknown as { buffer: Buffer; originalname: string }).buffer,
      (file as unknown as { buffer: Buffer; originalname: string }).originalname
    );
    return this.invoicesService.importPersonalInvoices(
      tenant.businessId,
      records
    );
  }

  @Post('company/import')
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(FileInterceptor('file'))
  @ApiConsumes('multipart/form-data')
  @ApiOperation({
    summary: 'Import company invoices from CSV or Excel',
    description:
      'Bulk import company invoices from a CSV or Excel file. Required columns: clientBusinessId, clientCompanyName, clientContactEmail, productId, quantity',
  })
  @ApiCreatedResponse({
    description: 'Company invoices imported successfully',
    schema: {
      type: 'object',
      properties: {
        imported: { type: 'number' },
        failed: { type: 'number' },
        errors: { type: 'array', items: { type: 'string' } },
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Invalid file format or data' })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  async importCompanyInvoices(
    @UploadedFile() file: Multer.File,
    @CurrentTenant() tenant: TenantContext
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    const records = await parseFile(
      (file as unknown as { buffer: Buffer; originalname: string }).buffer,
      (file as unknown as { buffer: Buffer; originalname: string }).originalname
    );
    return this.invoicesService.importCompanyInvoices(
      tenant.businessId,
      records
    );
  }
}
