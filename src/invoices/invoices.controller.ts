import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Headers,
  Param,
  Query,
  Req,
  HttpCode,
  HttpStatus,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  BadRequestException,
  ForbiddenException,
  Logger,
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
import type { Request } from 'express';
import {
  InvoiceIssuanceService,
  InvoiceReceiptService,
  InvoiceImportService,
  InvoicePaymentService,
} from '@/invoices/services';
import {
  CreateInvoiceDto,
  CreateInvoiceCheckoutSessionDto,
  MockInvoicePaymentDto,
  UpdateInvoiceDto,
  TransitionInvoiceStateDto,
  InvoiceCheckoutSessionResponseDto,
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
  private readonly logger = new Logger(InvoicesController.name);

  constructor(
    private readonly issuanceService: InvoiceIssuanceService,
    private readonly receiptService: InvoiceReceiptService,
    private readonly importService: InvoiceImportService,
    private readonly paymentService: InvoicePaymentService
  ) {}

  /**
   * ============================================
   * ISSUER ENDPOINTS (Tenant DB - Invoice Management)
   * ============================================
   * Routes used by businesses to create and manage invoices in their tenant database
   * Authentication: JWT + TenantContextGuard + BusinessRolesGuard
   * Only OWNER or ADMIN roles can access these routes
   * Data Storage: Tenant-specific MongoDB database (e.g., evenix_mn9fsurc_d1c76f)
   */

  @Post()
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: '[TENANT DB] Create a new invoice (draft)',
    description:
      'Create a new invoice in DRAFT state within the business tenant database. Invoice becomes visible to recipient when transitioned to ISSUED. ' +
      'Include businessId in the request body to resolve tenant context. ' +
      'Data is stored in: Tenant-specific MongoDB database.',
  })
  @ApiBody({
    description:
      'Create invoice payload with businessId to resolve tenant context.',
    type: CreateInvoiceDto,
  })
  @ApiCreatedResponse({
    description: 'Invoice created successfully in tenant database',
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
    summary: '[TENANT DB] List invoices issued by this business',
    description:
      'Retrieve all invoices created and managed by this business from the tenant database. ' +
      'businessId is REQUIRED as a query parameter. Data is stored in: Tenant-specific MongoDB database.',
  })
  @ApiOkResponse({
    description: 'List of issued invoices from tenant database',
    type: InvoiceListResponseDto,
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiQuery({
    name: 'status',
    required: false,
    description:
      'Filter by invoice status (DRAFT, ISSUED, PAID, OVERDUE, VIEWED)',
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
      tenant.databaseName,
      page,
      limit,
      { status: status }
    );
  }

  @Get('issued/:id')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: '[TENANT DB] Get a specific invoice issued by this business',
    description:
      'Retrieve a specific invoice from the tenant database. businessId is REQUIRED as a query parameter. ' +
      'Data is stored in: Tenant-specific MongoDB database.',
  })
  @ApiOkResponse({
    description: 'Invoice details from tenant database',
    type: InvoiceResponseDto,
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
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
    const invoice = await this.issuanceService.getInvoiceById(
      invoiceId,
      tenant.databaseName
    );
    // Verify issuer
    if (invoice.issuerBusinessId !== tenant.businessId) {
      throw new ForbiddenException('Forbidden');
    }
    return invoice;
  }

  @Patch('issued/:id')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: '[TENANT DB] Update a draft invoice',
    description:
      'Only DRAFT invoices can be edited. Once ISSUED, use state transitions instead. Include businessId in the request body to resolve tenant context. ' +
      'Data is stored in: Tenant-specific MongoDB database.',
  })
  @ApiOkResponse({
    description: 'Invoice updated in tenant database',
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
      tenant.databaseName,
      dto,
      user.id
    );
  }

  @Post('issued/:id/transition')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: '[TENANT DB] Transition invoice to a new state',
    description:
      'Change invoice status (DRAFT → ISSUED, ISSUED → PAID, etc.). Only valid transitions are allowed. Include businessId in the request body to resolve tenant context. ' +
      'Data is updated in: Tenant-specific MongoDB database and synced to Platform database for recipient visibility.',
  })
  @ApiOkResponse({
    description: 'Invoice state transitioned successfully',
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
   * RECIPIENT ENDPOINTS (Platform DB - Invoice Inbox)
   * ============================================
   * Routes used by businesses and individuals to receive and view invoices sent to them
   * Authentication: JWT + TenantContextGuard (for businesses) or JWT only (for individuals)
   * Data Storage: Platform-wide MongoDB database (accountia) - via InvoiceReceipts
   * These routes query invoice receipts to discover and access invoices from any issuer
   */

  @Get('received/business')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiOperation({
    summary: '[PLATFORM DB] Get invoices received by this business',
    description:
      'Retrieve all invoices issued to your business from any issuer. Data is queried from: Platform-wide MongoDB database (accountia) via InvoiceReceipts. ' +
      'businessId is REQUIRED as a query parameter.',
  })
  @ApiOkResponse({
    description: 'List of received invoices from platform database',
    type: InvoiceReceiptListResponseDto,
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiQuery({
    name: 'status',
    required: false,
    description:
      'Filter by invoice status (DRAFT, ISSUED, PAID, OVERDUE, VIEWED)',
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
    summary: '[PLATFORM DB] Get invoices received by you (individual)',
    description:
      'Retrieve all invoices issued to you personally from any business. Data is queried from: Platform-wide MongoDB database (accountia) via InvoiceReceipts.',
  })
  @ApiOkResponse({
    description: 'List of received invoices from platform database',
    type: InvoiceReceiptListResponseDto,
  })
  @ApiQuery({
    name: 'status',
    required: false,
    description:
      'Filter by invoice status (DRAFT, ISSUED, PAID, OVERDUE, VIEWED)',
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
    summary:
      '[PLATFORM DB → TENANT DB] Get full invoice details (business recipient)',
    description:
      "Fetch the authoritative invoice document from the issuer's tenant database. " +
      "Receipt lookup via: Platform database (accountia) | Full invoice data from: Issuer's tenant database. " +
      'businessId is REQUIRED as a query parameter.',
  })
  @ApiOkResponse({
    description: 'Full invoice details from issuer tenant database',
    type: InvoiceResponseDto,
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiNotFoundResponse({
    description: 'Invoice not found',
  })
  @ApiForbiddenResponse({
    description: 'You do not have access to this invoice',
  })
  @ApiParam({
    name: 'receiptId',
    description: 'Receipt ID from platform database',
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

  @Get('received/individual/:receiptId/details')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary:
      '[PLATFORM DB → TENANT DB] Get full invoice details (individual recipient)',
    description:
      "Fetch the authoritative invoice document from the issuer's tenant database for individual recipients. " +
      "Receipt lookup via: Platform database (accountia) | Full invoice data from: Issuer's tenant database.",
  })
  @ApiOkResponse({
    description: 'Full invoice details from issuer tenant database',
    type: InvoiceResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'You do not have access to this invoice',
  })
  @ApiParam({
    name: 'receiptId',
    description: 'Receipt ID from platform database',
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

  @Post('received/individual/:receiptId/payments/checkout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      '[STRIPE] Create payment checkout session for an individual recipient',
    description:
      'Creates a Stripe Checkout session so the recipient can securely pay an invoice online.',
  })
  @ApiOkResponse({
    description: 'Stripe checkout session created',
    type: InvoiceCheckoutSessionResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'You do not have access to this invoice receipt',
  })
  async createIndividualCheckoutSession(
    @Param('receiptId') receiptId: string,
    @CurrentUser() user: UserPayload,
    @Body() dto: CreateInvoiceCheckoutSessionDto
  ): Promise<InvoiceCheckoutSessionResponseDto> {
    return await this.paymentService.createCheckoutSession(
      receiptId,
      user,
      dto
    );
  }

  @Post('received/individual/:receiptId/payments/mock')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[DEMO] Simulate payment for an individual recipient',
    description:
      'Simulates an invoice payment without Stripe. Intended for demo or faculty environments only.',
  })
  @ApiOkResponse({
    description: 'Invoice marked as paid in demo mode',
    type: InvoiceResponseDto,
  })
  async createIndividualMockPayment(
    @Param('receiptId') receiptId: string,
    @CurrentUser() user: UserPayload,
    @Body() dto: MockInvoicePaymentDto
  ): Promise<InvoiceResponseDto> {
    return await this.paymentService.simulateIndividualPayment(
      receiptId,
      user,
      dto
    );
  }

  @Post('payments/webhook')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[STRIPE] Payment webhook',
    description:
      'Consumes Stripe webhook events to finalize invoice payments and update statuses.',
  })
  @ApiOkResponse({
    description: 'Webhook received',
    schema: { type: 'object', properties: { received: { type: 'boolean' } } },
  })
  async handleStripeWebhook(
    @Req() req: Request & { rawBody?: Buffer },
    @Headers('stripe-signature') stripeSignature?: string
  ): Promise<{ received: boolean }> {
    const rawBody = req.rawBody;
    if (!rawBody) {
      throw new BadRequestException(
        'Raw request body is required for webhook signature validation'
      );
    }

    await this.paymentService.handleStripeWebhook(stripeSignature, rawBody);
    return { received: true };
  }

  /**
   * ============================================
   * IMPORT ENDPOINTS (Tenant DB - Bulk Operations)
   * ============================================
   * Routes used by businesses to bulk import invoices from CSV/Excel files
   * Authentication: JWT + TenantContextGuard + BusinessRolesGuard
   * Only OWNER or ADMIN roles can access these routes
   * Data Storage: Tenant-specific MongoDB database (e.g., evenix_mn9fsurc_d1c76f)
   */

  @Get('import/template')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({
    summary: '[TENANT DB] Get import template and example',
    description:
      'Retrieve a CSV/Excel template and example format for bulk importing invoices. businessId is REQUIRED as a query parameter. ' +
      'Data invoices will be created in: Tenant-specific MongoDB database.',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
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
          'text/plain',
          'application/csv',
          'text/x-csv',
          'application/vnd.ms-excel',
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        ];

        const originalName = (file.originalname ?? '').toLowerCase();
        const hasAllowedExtension =
          originalName.endsWith('.csv') ||
          originalName.endsWith('.xls') ||
          originalName.endsWith('.xlsx');

        if (allowedMimes.includes(file.mimetype) || hasAllowedExtension) {
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
    summary: '[TENANT DB] Bulk import invoices from CSV or Excel file',
    description:
      'Import multiple invoices at once from a CSV or XLSX file. ' +
      'Each row represents one invoice. Supports multiple recipient types and line item formats. ' +
      'Use GET /invoices/import/template to get the required format. ' +
      'Data is created in: Tenant-specific MongoDB database and synced to Platform database for recipient visibility.',
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
