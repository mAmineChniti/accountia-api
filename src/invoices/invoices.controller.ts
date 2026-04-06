import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  BadRequestException,
} from '@nestjs/common';
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
  ApiBody,
} from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  InvoiceIssuanceService,
  InvoiceReceiptService,
  InvoiceImportService,
} from '@/invoices/services';
import {
  CreateInvoiceDto,
  UpdateInvoiceDto,
  TransitionInvoiceStateDto,
  InvoiceResponseDto,
  InvoiceListResponseDto,
  InvoiceReceiptListResponseDto,
} from '@/invoices/dto/invoice.dto';
import {
  BulkImportInvoicesResponseDto,
  ImportTemplateResponseDto,
} from '@/invoices/dto/invoice-import.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import {
  BusinessRolesGuard,
  BusinessRoles,
} from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import type { TenantContext } from '@/common/tenant/tenant.types';
import type { UserPayload } from '@/auth/types/auth.types';

@ApiTags('Invoices')
@ApiBearerAuth()
@Controller('invoices')
export class InvoicesController {
  constructor(
    private readonly issuanceService: InvoiceIssuanceService,
    private readonly receiptService: InvoiceReceiptService,
    private readonly importService: InvoiceImportService
  ) {}

  /**
   * ============================================
   * ISSUER ENDPOINTS (Invoice Management)
   * ============================================
   * Only businesses that issued the invoice can manage them
   */

  @Post()
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a new invoice (draft)',
    description:
      'Create a new invoice in DRAFT state. Invoice becomes visible to recipient when transitioned to ISSUED. Include businessId in the request body to resolve tenant context.',
  })
  @ApiBody({
    description:
      'Create invoice payload with businessId to resolve tenant context.',
    type: CreateInvoiceDto,
  })
  @ApiCreatedResponse({
    description: 'Invoice created successfully',
    type: InvoiceResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Invalid input or duplicate invoice number',
  })
  async createInvoice(
    @Body() dto: CreateInvoiceDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return await this.issuanceService.createDraftInvoice(
      tenant.businessId,
      tenant.databaseName,
      dto,
      user.id
    );
  }

  @Get('issued')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: 'List invoices issued by this business',
    description:
      'Retrieve all invoices created and managed by this business. Provide businessId in the request body to resolve tenant context.',
  })
  @ApiOkResponse({
    description: 'List of issued invoices',
    type: InvoiceListResponseDto,
  })
  @ApiQuery({
    name: 'status',
    required: false,
    description: 'Filter by invoice status (DRAFT, ISSUED, PAID, etc.)',
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
  async listIssuedInvoices(
    @CurrentTenant() tenant: TenantContext,
    @Query('status') status?: string,
    @Query('page') page = 1,
    @Query('limit') limit = 10
  ): Promise<InvoiceListResponseDto> {
    return await this.issuanceService.getIssuerInvoices(
      tenant.businessId,
      page,
      limit,
      { status: status }
    );
  }

  @Get('issued/:id')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: 'Get a specific invoice issued by this business',
    description:
      'Retrieve a specific invoice. Include businessId in the request body to resolve tenant context.',
  })
  @ApiOkResponse({
    description: 'Invoice details',
    type: InvoiceResponseDto,
  })
  @ApiNotFoundResponse({
    description: 'Invoice not found',
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async getIssuedInvoice(
    @Param('id') invoiceId: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.issuanceService.getInvoiceById(invoiceId);
    // Verify issuer
    if (invoice.issuerBusinessId !== tenant.businessId) {
      throw new Error('Forbidden');
    }
    return invoice;
  }
  @Get('business/:businessId/issued/:id')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: 'Get a specific invoice issued by this business (businessId path)',
    description:
      'Retrieve invoice details by businessId and invoiceId. This is a direct route for front-end View buttons.',
  })
  @ApiOkResponse({
    description: 'Invoice details',
    type: InvoiceResponseDto,
  })
  @ApiNotFoundResponse({
    description: 'Invoice not found',
  })
  @ApiParam({
    name: 'businessId',
    description: 'Business ID',
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async getIssuedInvoiceByBusiness(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<InvoiceResponseDto> {
    if (tenant.businessId !== businessId) {
      throw new Error('Forbidden');
    }
    return this.getIssuedInvoice(invoiceId, tenant);
  }
  @Get('issued/:id/details')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: 'Get a specific invoice issued by this business (details alias)',
    description:
      'Retrieve a specific invoice details view. Alias for issued/:id for UI convenience.',
  })
  @ApiOkResponse({
    description: 'Invoice details',
    type: InvoiceResponseDto,
  })
  @ApiNotFoundResponse({
    description: 'Invoice not found',
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async getIssuedInvoiceDetailsAlias(
    @Param('id') invoiceId: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<InvoiceResponseDto> {
    return this.getIssuedInvoice(invoiceId, tenant);
  }

  @Patch('issued/:id')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: 'Update a draft invoice',
    description:
      'Only DRAFT invoices can be edited. Once ISSUED, use state transitions instead. Include businessId in the request body to resolve tenant context.',
  })
  @ApiOkResponse({
    description: 'Invoice updated',
    type: InvoiceResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Cannot update non-draft invoice',
  })
  @ApiBody({
    description:
      'Draft invoice update payload with businessId to resolve tenant context.',
    type: UpdateInvoiceDto,
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async updateDraftInvoice(
    @Param('id') invoiceId: string,
    @Body() dto: UpdateInvoiceDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return await this.issuanceService.updateDraftInvoice(
      invoiceId,
      tenant.businessId,
      dto,
      user.id
    );
  }

  @Post('issued/:id/transition')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: 'Transition invoice to a new state',
    description:
      'Change invoice status (DRAFT → ISSUED, ISSUED → PAID, etc.). Only valid transitions are allowed. Include businessId in the request body to resolve tenant context.',
  })
  @ApiOkResponse({
    description: 'Invoice state transitioned',
    type: InvoiceResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Invalid state transition',
  })
  @ApiBody({
    description:
      'Invoice state transition payload with businessId to resolve tenant context.',
    type: TransitionInvoiceStateDto,
  })
  @ApiParam({
    name: 'id',
    description: 'Invoice ID',
  })
  async transitionInvoiceState(
    @Param('id') invoiceId: string,
    @Body() dto: TransitionInvoiceStateDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return await this.issuanceService.transitionInvoiceState(
      invoiceId,
      tenant.businessId,
      tenant.databaseName,
      dto,
      user.id
    );
  }

  /**
   * ============================================
   * RECIPIENT ENDPOINTS (Invoice Inbox)
   * ============================================
   * Any authenticated user/business can view invoices addressed to them
   */

  @Get('received/business')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiOperation({
    summary: 'Get invoices received by this business',
    description:
      'Retrieve all invoices issued to your business by any issuer. Provide businessId in the request body to resolve tenant context.',
  })
  @ApiOkResponse({
    description: 'List of received invoices',
    type: InvoiceReceiptListResponseDto,
  })
  @ApiQuery({
    name: 'status',
    required: false,
    description: 'Filter by invoice status',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
  })
  async getReceivedByBusiness(
    @CurrentTenant() tenant: TenantContext,
    @Query('status') status?: string,
    @Query('page') page = 1,
    @Query('limit') limit = 10
  ): Promise<InvoiceReceiptListResponseDto> {
    return await this.receiptService.getReceivedInvoicesByBusiness(
      tenant.businessId,
      page,
      limit,
      { status }
    );
  }

  @Get('received/individual')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: 'Get invoices received by you',
    description: 'Retrieve all invoices issued to you by any business',
  })
  @ApiOkResponse({
    description: 'List of received invoices',
    type: InvoiceReceiptListResponseDto,
  })
  @ApiQuery({
    name: 'status',
    required: false,
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
  })
  async getReceivedByIndividual(
    @CurrentUser() user: UserPayload,
    @Query('status') status?: string,
    @Query('page') page = 1,
    @Query('limit') limit = 10
  ): Promise<InvoiceReceiptListResponseDto> {
    return await this.receiptService.getReceivedInvoicesByIndividual(
      user.id,
      user.email,
      page,
      limit,
      { status }
    );
  }

  @Get('received/:receiptId/details')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiOperation({
    summary: 'Get full invoice details (business recipient)',
    description:
      "Fetch the authoritative invoice document from the issuer's database. Include businessId in the request body to resolve tenant context.",
  })
  @ApiOkResponse({
    description: 'Full invoice details',
    type: InvoiceResponseDto,
  })
  @ApiNotFoundResponse({
    description: 'Invoice not found',
  })
  @ApiForbiddenResponse({
    description: 'You do not have access to this invoice',
  })
  @ApiParam({
    name: 'receiptId',
    description: 'Receipt ID',
  })
  async getReceivedInvoiceDetails(
    @Param('receiptId') receiptId: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<InvoiceResponseDto> {
    return await this.receiptService.getInvoiceDetailsAsRecipient(
      receiptId,
      tenant.businessId
    );
  }

  @Get('business/:businessId/received/:receiptId')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiOperation({
    summary: 'Get full invoice details (business recipient by businessId path)',
    description:
      'Fetch the invoice details using a businessId and receiptId in the URL. Useful for front-end View button calls.',
  })
  @ApiOkResponse({
    description: 'Full invoice details',
    type: InvoiceResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'You do not have access to this invoice',
  })
  @ApiParam({
    name: 'businessId',
    description: 'Business ID',
  })
  @ApiParam({
    name: 'receiptId',
    description: 'Receipt ID',
  })
  async getReceivedInvoiceDetailsByBusiness(
    @Param('businessId') businessId: string,
    @Param('receiptId') receiptId: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<InvoiceResponseDto> {
    if (tenant.businessId !== businessId) {
      throw new Error('Forbidden');
    }
    return this.getReceivedInvoiceDetails(receiptId, tenant);
  }

  @Get('received/:receiptId')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiOperation({
    summary: 'Get full invoice details (business recipient alias)',
    description:
      'Fetch the invoice details using a shorter URL. Useful for direct View button links.',
  })
  @ApiOkResponse({
    description: 'Full invoice details',
    type: InvoiceResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'You do not have access to this invoice',
  })
  @ApiParam({
    name: 'receiptId',
    description: 'Receipt ID',
  })
  async getReceivedInvoiceDetailsAlias(
    @Param('receiptId') receiptId: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<InvoiceResponseDto> {
    return this.getReceivedInvoiceDetails(receiptId, tenant);
  }

  @Get('received/individual/:receiptId/details')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: 'Get full invoice details (individual recipient)',
    description:
      'Fetch the authoritative invoice document (for individual recipients)',
  })
  @ApiOkResponse({
    description: 'Full invoice details',
    type: InvoiceResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'You do not have access to this invoice',
  })
  @ApiParam({
    name: 'receiptId',
    description: 'Receipt ID',
  })
  async getReceivedInvoiceDetailsIndividual(
    @Param('receiptId') receiptId: string,
    @CurrentUser() user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return await this.receiptService.getInvoiceDetailsAsRecipient(
      receiptId,
      undefined,
      user.id,
      user.email
    );
  }

  /**
   * ============================================
   * IMPORT ENDPOINTS (Bulk Operations)
   * ============================================
   * Import invoices in bulk from CSV or Excel files
   */

  @Get('import/template')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: 'Get import template and example',
    description:
      'Retrieve a CSV/Excel template and example format for bulk importing invoices',
  })
  @ApiOkResponse({
    description: 'Import template with examples and column definitions',
    type: ImportTemplateResponseDto,
  })
  getImportTemplate(): ImportTemplateResponseDto {
    return this.importService.getImportTemplate();
  }

  @Post('import')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @UseInterceptors(
    FileInterceptor('file', {
      limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
      fileFilter: (req, file, cb) => {
        const allowedMimes = [
          'text/csv',
          'application/vnd.ms-excel',
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        ];
        if (allowedMimes.includes(file.mimetype)) {
          // eslint-disable-next-line unicorn/no-null
          cb(null, true);
        } else {
          cb(
            new BadRequestException('Only CSV and XLSX files are allowed'),
            false
          );
        }
      },
    })
  )
  @HttpCode(HttpStatus.OK)
  @ApiConsumes('multipart/form-data')
  @ApiOperation({
    summary: 'Bulk import invoices from CSV or Excel file',
    description:
      'Import multiple invoices at once from a CSV or XLSX file. ' +
      'Each row represents one invoice. Supports multiple recipient types and line item formats. ' +
      'Use GET /invoices/import/template to get the required format.',
  })
  @ApiOkResponse({
    description: 'Import completed with detailed results',
    type: BulkImportInvoicesResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Invalid file format or structure',
  })
  async importInvoicesFromFile(
    @UploadedFile() file: { originalname: string; buffer: Buffer } | undefined,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<BulkImportInvoicesResponseDto> {
    if (!file) {
      throw new BadRequestException('File is required');
    }
    return await this.importService.importInvoicesFromFile(
      file,
      tenant.businessId,
      tenant.databaseName,
      user.id
    );
  }
}
