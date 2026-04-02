import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiResponse,
  ApiParam,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { InvoicesService } from './invoices.service';
import { CreateInvoiceDto } from './dto/create-invoice.dto';
import { UpdateInvoiceDto } from './dto/update-invoice.dto';
import { InvoiceResponseDto } from './dto/invoice-response.dto';
import { InvoiceStatus } from '@/invoices/schemas/invoice.schema';
import { BusinessService } from '@/business/business.service';

@ApiTags('Invoices')
@Controller('business/:businessId/invoices')
@UseGuards(JwtAuthGuard, TenantContextGuard)
@ApiBearerAuth()
@ApiResponse({
  status: 401,
  description: 'Unauthorized - Invalid or missing JWT token',
})
@ApiResponse({
  status: 403,
  description: 'Forbidden - Insufficient permissions',
})
@ApiResponse({
  status: 404,
  description: 'Not Found - Invoice or business not found',
})
@ApiResponse({ status: 500, description: 'Internal Server Error' })
export class InvoicesController {
  constructor(
    private invoicesService: InvoicesService,
    private businessService: BusinessService
  ) {}

  /**
   * Create a new invoice
   * POST /business/:businessId/invoices
   */
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a new invoice',
    description: 'Create a new invoice for a business',
  })
  @ApiCreatedResponse({
    description: 'Invoice created successfully',
    type: InvoiceResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid input data or validation errors',
  })
  async createInvoice(
    @Param('businessId') businessId: string,
    @Body() createInvoiceDto: CreateInvoiceDto,
    @CurrentUser() _user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return this.invoicesService.createInvoice(businessId, createInvoiceDto);
  }

  /**
   * Get all invoices for a business
   * GET /business/:businessId/invoices
   */
  @Get()
  @ApiOperation({
    summary: 'Get all invoices for a business',
    description: 'Retrieve paginated list of invoices for a specific business',
  })
  @ApiOkResponse({
    description: 'List of invoices retrieved successfully',
    type: [InvoiceResponseDto],
  })
  async getInvoices(
    @Param('businessId') businessId: string,
    @CurrentUser() _user: UserPayload,
    @Query('status') status?: InvoiceStatus,
    @Query('page') page = 1,
    @Query('limit') limit = 10
  ): Promise<{
    invoices: InvoiceResponseDto[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    return this.invoicesService.getInvoicesByBusinessId(
      businessId,
      status,
      Math.max(1, page),
      Math.max(1, limit)
    );
  }

  /**
   * Get a specific invoice
   * GET /business/:businessId/invoices/:id
   */
  @Get(':id')
  @ApiOperation({
    summary: 'Get a specific invoice',
    description: 'Retrieve details of a specific invoice',
  })
  @ApiOkResponse({
    description: 'Invoice retrieved successfully',
    type: InvoiceResponseDto,
  })
  @ApiParam({ name: 'id', description: 'Invoice ID' })
  async getInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentUser() _user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return this.invoicesService.getInvoiceById(invoiceId, businessId);
  }

  /**
   * Update an invoice
   * PATCH /business/:businessId/invoices/:id
   */
  @Patch(':id')
  @ApiOperation({
    summary: 'Update a draft invoice',
    description: 'Update details of a draft invoice',
  })
  @ApiOkResponse({
    description: 'Invoice updated successfully',
    type: InvoiceResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Cannot update non-draft invoice',
  })
  @ApiParam({ name: 'id', description: 'Invoice ID' })
  async updateInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Body() updateInvoiceDto: UpdateInvoiceDto,
    @CurrentUser() _user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return this.invoicesService.updateInvoice(
      invoiceId,
      businessId,
      updateInvoiceDto
    );
  }

  /**
   * Delete an invoice (soft delete)
   * DELETE /business/:businessId/invoices/:id
   */
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete an invoice',
    description: 'Soft delete an invoice (can only delete draft invoices)',
  })
  @ApiResponse({
    status: 204,
    description: 'Invoice deleted successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Cannot delete non-draft invoice',
  })
  @ApiParam({ name: 'id', description: 'Invoice ID' })
  async deleteInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentUser() _user: UserPayload
  ): Promise<void> {
    await this.invoicesService.deleteInvoice(invoiceId, businessId);
  }

  /**
   * Send an invoice to client
   * POST /business/:businessId/invoices/:id/send
   */
  @Post(':id/send')
  @ApiOperation({
    summary: 'Send an invoice to client',
    description: 'Mark invoice as SENT and send notification email to client',
  })
  @ApiOkResponse({
    description: 'Invoice sent successfully',
    type: InvoiceResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Cannot send already sent invoice',
  })
  @ApiParam({ name: 'id', description: 'Invoice ID' })
  async sendInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Body() body: { customMessage?: string },
    @CurrentUser() _user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return this.invoicesService.sendInvoice(
      invoiceId,
      businessId,
      body?.customMessage
    );
  }

  /**
   * Manually mark invoice as paid
   * POST /business/:businessId/invoices/:id/mark-paid
   */
  @Post(':id/mark-paid')
  @ApiOperation({
    summary: 'Manually mark invoice as paid',
    description: 'Mark an invoice as paid without payment processing',
  })
  @ApiOkResponse({
    description: 'Invoice marked as paid successfully',
    type: InvoiceResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Cannot mark already paid invoice',
  })
  @ApiParam({ name: 'id', description: 'Invoice ID' })
  async markAsPaidManual(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentUser() _user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return this.invoicesService.markInvoiceAsPaidManual(invoiceId, businessId);
  }

  /**
   * Toggle payment reminders for an invoice
   * PATCH /business/:businessId/invoices/:id/reminders
   */
  @Patch(':id/reminders')
  @ApiOperation({
    summary: 'Toggle payment reminders',
    description: 'Enable or disable automatic payment reminders for an invoice',
  })
  @ApiOkResponse({
    description: 'Invoice reminders toggled successfully',
    type: InvoiceResponseDto,
  })
  @ApiParam({ name: 'id', description: 'Invoice ID' })
  async toggleReminders(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Body() body: { muted: boolean },
    @CurrentUser() _user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return this.invoicesService.toggleInvoiceReminders(
      invoiceId,
      businessId,
      body.muted
    );
  }

  /**
   * Manually send payment reminder
   * POST /business/:businessId/invoices/:id/remind
   */
  @Post(':id/remind')
  @ApiOperation({
    summary: 'Manually send a payment reminder',
    description: 'Send an immediate reminder email to invoice client',
  })
  @ApiOkResponse({
    description: 'Reminder sent successfully',
    type: InvoiceResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Cannot remind on draft or paid invoices',
  })
  @ApiParam({ name: 'id', description: 'Invoice ID' })
  async sendReminder(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentUser() _user: UserPayload
  ): Promise<InvoiceResponseDto> {
    return this.invoicesService.sendManualReminder(invoiceId, businessId);
  }

  /**
   * Get invoices for authenticated client
   * GET /invoices/client/my
   *
   * Returns only invoices addressed to the authenticated user's email
   */
  @Get('client/my')
  @ApiOperation({
    summary: 'Get my invoices (client endpoint)',
    description:
      'Retrieve your invoices (for regular clients, not business owners)',
  })
  @ApiOkResponse({
    description: 'Invoices retrieved successfully',
    type: [InvoiceResponseDto],
  })
  async getMyInvoices(
    @CurrentUser() user: UserPayload,
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('status') status?: InvoiceStatus
  ): Promise<{
    invoices: InvoiceResponseDto[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    return this.invoicesService.getInvoicesByUserId(
      user.id,
      status,
      Math.max(1, page),
      Math.max(1, limit)
    );
  }
}
