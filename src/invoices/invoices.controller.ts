import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { InvoicesService } from './invoices.service';
import {
  CreateInvoiceDto,
  UpdateInvoiceStatusDto,
  InvoiceResponseDto,
  InvoicesListResponseDto,
} from './dto/invoice.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { AdminGuard } from '@/auth/guards/admin.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { Role } from '@/users/schemas/user.schema';
import { ForbiddenException } from '@nestjs/common';

@ApiTags('Invoices')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('invoices')
export class InvoicesController {
  constructor(private readonly invoicesService: InvoicesService) {}

  // ─── CLIENT: ses propres factures ──────────────────────────────────────

  @Get('my')
  @ApiOperation({ summary: 'CLIENT — Get my invoices' })
  @ApiResponse({ status: 200, type: InvoicesListResponseDto })
  async getMyInvoices(
    @CurrentUser() user: UserPayload
  ): Promise<InvoicesListResponseDto> {
    return this.invoicesService.getMyInvoices(user.id);
  }

  @Get('my/:id')
  @ApiOperation({ summary: 'CLIENT — Get one of my invoices' })
  @ApiResponse({ status: 200, type: InvoiceResponseDto })
  async getMyInvoiceById(
    @CurrentUser() user: UserPayload,
    @Param('id') id: string
  ): Promise<InvoiceResponseDto> {
    return this.invoicesService.getMyInvoiceById(user.id, id);
  }

  // ─── BUSINESS_OWNER: factures émises ──────────────────────────────────

  @Get('issued')
  @ApiOperation({ summary: 'BUSINESS_OWNER — Get invoices I issued' })
  @ApiResponse({ status: 200, type: InvoicesListResponseDto })
  async getIssuedInvoices(
    @CurrentUser() user: UserPayload
  ): Promise<InvoicesListResponseDto> {
    if (
      user.role !== Role.BUSINESS_OWNER &&
      user.role !== Role.BUSINESS_ADMIN
    ) {
      throw new ForbiddenException(
        'Only business owners or business admins can access this'
      );
    }
    return this.invoicesService.getMyIssuedInvoices(user.id);
  }

  @Post()
  @ApiOperation({ summary: 'BUSINESS_OWNER — Create invoice for a client' })
  @ApiResponse({ status: 201, type: InvoiceResponseDto })
  async createInvoice(
    @CurrentUser() user: UserPayload,
    @Body() dto: CreateInvoiceDto
  ): Promise<InvoiceResponseDto> {
    if (
      user.role !== Role.BUSINESS_OWNER &&
      user.role !== Role.BUSINESS_ADMIN
    ) {
      throw new ForbiddenException(
        'Only business owners or business admins can create invoices'
      );
    }
    return this.invoicesService.createInvoice(user.id, dto);
  }

  @Patch(':id/status')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'BUSINESS_OWNER — Update invoice status' })
  @ApiResponse({ status: 200, type: InvoiceResponseDto })
  async updateStatus(
    @CurrentUser() user: UserPayload,
    @Param('id') id: string,
    @Body() dto: UpdateInvoiceStatusDto
  ): Promise<InvoiceResponseDto> {
    if (
      user.role !== Role.BUSINESS_OWNER &&
      user.role !== Role.BUSINESS_ADMIN
    ) {
      throw new ForbiddenException(
        'Only business owners or business admins can update invoice status'
      );
    }
    return this.invoicesService.updateInvoiceStatus(user.id, id, dto.status);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'BUSINESS_OWNER — Delete an invoice' })
  @ApiResponse({ status: 200, description: 'Invoice deleted' })
  async deleteInvoice(
    @CurrentUser() user: UserPayload,
    @Param('id') id: string
  ): Promise<{ message: string }> {
    if (
      user.role !== Role.BUSINESS_OWNER &&
      user.role !== Role.BUSINESS_ADMIN
    ) {
      throw new ForbiddenException(
        'Only business owners or business admins can delete invoices'
      );
    }
    await this.invoicesService.deleteInvoice(user.id, id);
    return { message: 'Invoice deleted successfully' };
  }

  // ─── ADMIN: toutes les factures ────────────────────────────────────────

  @Get('admin/all')
  @UseGuards(AdminGuard)
  @ApiOperation({ summary: 'ADMIN — Get all invoices' })
  @ApiResponse({ status: 200, type: InvoicesListResponseDto })
  async getAllInvoices(): Promise<InvoicesListResponseDto> {
    return this.invoicesService.getAllInvoices();
  }
}
