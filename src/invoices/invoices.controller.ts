import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Req,
  BadRequestException,
  Query,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { InvoicesService } from './invoices.service';
import { CreateInvoiceDto } from './dto/create-invoice.dto';
import { UpdateInvoiceDto } from './dto/update-invoice.dto';
import { InvoiceResponseDto, InvoiceListResponseDto } from './dto/invoice-response.dto';
import { InvoiceStatus } from '@/business/schemas/invoice.schema';
import { BusinessService } from '@/business/business.service';

@Controller('business/:businessId/invoices')
@UseGuards(JwtAuthGuard)
export class InvoicesController {
  constructor(
    private invoicesService: InvoicesService,
    private businessService: BusinessService,
  ) {}

  /**
   * Crée une nouvelle facture
   * POST /business/:businessId/invoices
   */
  @Post()
  async createInvoice(
    @Param('businessId') businessId: string,
    @Body() createInvoiceDto: CreateInvoiceDto,
    @Req() req: any,
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      console.log('[InvoicesController.createInvoice] Request details:', {
        businessIdParam: businessId,
        userRole: req.user?.role,
        userBusinessId: req.user?.businessId,
        userId: req.user?.userId,
      });

      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(businessId, req.user.id, req.user.role);

      // ✅ FIXED: Pass businessId as the owner context and req.user.id for tracking if needed
      // Actually, createInvoice expects businessOwnerId (which should be businessId)
      const invoice = await this.invoicesService.createInvoice(businessId, createInvoiceDto);
      console.log(`[InvoicesController.createInvoice] ✅ Created invoice for business ${businessId} by user ${req.user.id}:`, {
        invoiceId: invoice.id,
        invoiceNumber: invoice.invoiceNumber,
      });
      return { success: true, data: invoice };
    } catch (error: any) {
      console.error('[InvoicesController.createInvoice] ❌ Error:', error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Récupère toutes les factures d'un business
   * GET /business/:businessId/invoices
   */
  @Get()
  async getInvoices(
    @Param('businessId') businessId: string,
    @Req() req: any,
    @Query('status') status?: InvoiceStatus,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
  ): Promise<{ success: boolean; invoices?: InvoiceResponseDto[]; total?: number; error?: string }> {
    try {
      console.log('[InvoicesController.getInvoices] Request details:', {
        businessIdParam: businessId,
        userRole: req.user?.role,
        userBusinessId: req.user?.businessId,
        userId: req.user?.userId,
      });

      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(businessId, req.user.id, req.user.role);

      // ✅ FIXED: Search by businessId
      const result = await this.invoicesService.getInvoicesByBusinessId(
        businessId,
        status,
        Math.max(1, page),
        Math.max(1, limit),
      );

      console.log(`[InvoicesController.getInvoices] ✅ Found ${result.invoices.length} invoices for business ${businessId}`);

      return {
        success: true,
        invoices: result.invoices,
        total: result.total,
      };
    } catch (error: any) {
      console.error('[InvoicesController.getInvoices] ❌ Error:', error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Récupère une facture spécifique
   * GET /business/:businessId/invoices/:id
   */
  @Get(':id')
  async getInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Req() req: any,
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(businessId, req.user.id, req.user.role);

      const invoice = await this.invoicesService.getInvoiceById(invoiceId, businessId);
      return { success: true, data: invoice };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Met à jour une facture
   * PATCH /business/:businessId/invoices/:id
   */
  @Patch(':id')
  async updateInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Body() updateInvoiceDto: UpdateInvoiceDto,
    @Req() req: any,
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(businessId, req.user.id, req.user.role);

      const invoice = await this.invoicesService.updateInvoice(invoiceId, businessId, updateInvoiceDto);
      return { success: true, data: invoice };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Supprime une facture (soft delete)
   * DELETE /business/:businessId/invoices/:id
   */
  @Delete(':id')
  async deleteInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Req() req: any,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(businessId, req.user.id, req.user.role);

      await this.invoicesService.deleteInvoice(invoiceId, businessId);
      return { success: true };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Envoie une facture
   * POST /business/:businessId/invoices/:id/send
   */
  @Post(':id/send')
  async sendInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Body() body: { customMessage?: string },
    @Req() req: any,
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(businessId, req.user.id, req.user.role);

      const invoice = await this.invoicesService.sendInvoice(invoiceId, businessId, body?.customMessage);
      return { success: true, data: invoice };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Marque manuellement une facture comme payée
   * POST /business/:businessId/invoices/:id/mark-paid
   */
  @Post(':id/mark-paid')
  async markAsPaidManual(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Req() req: any,
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      await this.businessService.checkBusinessAccess(businessId, req.user.id, req.user.role);

      const invoice = await this.invoicesService.markInvoiceAsPaidManual(invoiceId, businessId);
      return { success: true, data: invoice };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }
}
