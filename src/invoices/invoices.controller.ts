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
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { InvoicesService } from './invoices.service';
import { CreateInvoiceDto } from './dto/create-invoice.dto';
import { UpdateInvoiceDto } from './dto/update-invoice.dto';
import { InvoiceResponseDto } from './dto/invoice-response.dto';
import { InvoiceStatus } from '@/business/schemas/invoice.schema';
import { BusinessService } from '@/business/business.service';

@ApiTags('Invoices')
@Controller('business/:businessId/invoices')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class InvoicesController {
  constructor(
    private invoicesService: InvoicesService,
    private businessService: BusinessService
  ) {}

  /**
   * Crée une nouvelle facture
   * POST /business/:businessId/invoices
   */
  @Post()
  @ApiCreatedResponse({
    description: 'Invoice created successfully',
    type: InvoiceResponseDto,
  })
  async createInvoice(
    @Param('businessId') businessId: string,
    @Body() createInvoiceDto: CreateInvoiceDto,
    @CurrentUser() user: UserPayload
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      console.log('[InvoicesController.createInvoice] Request details:', {
        businessIdParam: businessId,
        userRole: user.role,
        userId: user.id,
      });

      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      // ✅ FIXED: Pass businessId as the owner context
      const invoice = await this.invoicesService.createInvoice(
        businessId,
        createInvoiceDto
      );
      console.log(
        `[InvoicesController.createInvoice] ✅ Created invoice for business ${businessId} by user ${user.id}:`,
        {
          invoiceId: invoice.id,
          invoiceNumber: invoice.invoiceNumber,
        }
      );
      return { success: true, data: invoice };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      console.error('[InvoicesController.createInvoice] ❌ Error:', message);
      return { success: false, error: message };
    }
  }

  /**
   * Récupère toutes les factures d'un business
   * GET /business/:businessId/invoices
   */
  @Get()
  @ApiOkResponse({
    description: 'List of invoices retrieved successfully',
    type: [InvoiceResponseDto],
  })
  async getInvoices(
    @Param('businessId') businessId: string,
    @CurrentUser() user: UserPayload,
    @Query('status') status?: InvoiceStatus,
    @Query('page') page = 1,
    @Query('limit') limit = 10
  ): Promise<{
    success: boolean;
    invoices?: InvoiceResponseDto[];
    total?: number;
    error?: string;
  }> {
    try {
      console.log('[InvoicesController.getInvoices] Request details:', {
        businessIdParam: businessId,
        userRole: user.role,
        userId: user.id,
      });

      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      // ✅ FIXED: Search by businessId
      const result = await this.invoicesService.getInvoicesByBusinessId(
        businessId,
        status,
        Math.max(1, page),
        Math.max(1, limit)
      );

      console.log(
        `[InvoicesController.getInvoices] ✅ Found ${result.invoices.length} invoices for business ${businessId}`
      );

      return {
        success: true,
        invoices: result.invoices,
        total: result.total,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      console.error('[InvoicesController.getInvoices] ❌ Error:', message);
      return { success: false, error: message };
    }
  }

  /**
   * Récupère une facture spécifique
   * GET /business/:businessId/invoices/:id
   */
  @Get(':id')
  @ApiOkResponse({
    description: 'Invoice retrieved successfully',
    type: InvoiceResponseDto,
  })
  async getInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentUser() user: UserPayload
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      const invoice = await this.invoicesService.getInvoiceById(
        invoiceId,
        businessId
      );
      return { success: true, data: invoice };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }

  /**
   * Met à jour une facture
   * PATCH /business/:businessId/invoices/:id
   */
  @Patch(':id')
  @ApiOkResponse({
    description: 'Invoice updated successfully',
    type: InvoiceResponseDto,
  })
  async updateInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Body() updateInvoiceDto: UpdateInvoiceDto,
    @CurrentUser() user: UserPayload
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      const invoice = await this.invoicesService.updateInvoice(
        invoiceId,
        businessId,
        updateInvoiceDto
      );
      return { success: true, data: invoice };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }

  /**
   * Supprime une facture (soft delete)
   * DELETE /business/:businessId/invoices/:id
   */
  @Delete(':id')
  @ApiOkResponse({
    description: 'Invoice deleted successfully',
  })
  async deleteInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentUser() user: UserPayload
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      await this.invoicesService.deleteInvoice(invoiceId, businessId);
      return { success: true };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }

  /**
   * Envoie une facture
   * POST /business/:businessId/invoices/:id/send
   */
  @Post(':id/send')
  @ApiOkResponse({
    description: 'Invoice sent successfully',
    type: InvoiceResponseDto,
  })
  async sendInvoice(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Body() body: { customMessage?: string },
    @CurrentUser() user: UserPayload
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      // Vérifier que l'utilisateur appartient à ce business
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      const invoice = await this.invoicesService.sendInvoice(
        invoiceId,
        businessId,
        body?.customMessage
      );
      return { success: true, data: invoice };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }

  /**
   * Marque manuellement une facture comme payée
   * POST /business/:businessId/invoices/:id/mark-paid
   */
  @Post(':id/mark-paid')
  @ApiOkResponse({
    description: 'Invoice marked as paid successfully',
    type: InvoiceResponseDto,
  })
  async markAsPaidManual(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentUser() user: UserPayload
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      const invoice = await this.invoicesService.markInvoiceAsPaidManual(
        invoiceId,
        businessId
      );
      return { success: true, data: invoice };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }

  /**
   * Active ou désactive les rappels pour une facture spécifique
   * PATCH /business/:businessId/invoices/:id/reminders
   */
  @Patch(':id/reminders')
  @ApiOkResponse({
    description: 'Invoice reminders toggled successfully',
    type: InvoiceResponseDto,
  })
  async toggleReminders(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @Body() body: { muted: boolean },
    @CurrentUser() user: UserPayload
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      const invoice = await this.invoicesService.toggleInvoiceReminders(
        invoiceId,
        businessId,
        body.muted
      );
      return { success: true, data: invoice };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }

  /**
   * Envoie manuellement un rappel de paiement
   * POST /business/:businessId/invoices/:id/remind
   */
  @Post(':id/remind')
  @ApiOkResponse({
    description: 'Reminder sent successfully',
    type: InvoiceResponseDto,
  })
  async sendReminder(
    @Param('businessId') businessId: string,
    @Param('id') invoiceId: string,
    @CurrentUser() user: UserPayload
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      await this.businessService.checkBusinessAccess(
        businessId,
        user.id,
        user.role
      );

      const invoice = await this.invoicesService.sendManualReminder(
        invoiceId,
        businessId
      );
      return { success: true, data: invoice };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      console.error('[InvoicesController.sendReminder] Error:', message);
      return { success: false, error: message };
    }
  }
}
