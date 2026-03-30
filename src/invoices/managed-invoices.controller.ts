import {
  Controller,
  Get,
  Query,
  Req,
  UseGuards,
  Param,
  Post,
  Body,
} from '@nestjs/common';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { InvoicesService } from './invoices.service';
import { FlouciService } from './flouci.service';
import { InvoiceResponseDto } from './dto/invoice-response.dto';

/**
 * Contrôleur pour les invoices des clients MANAGÉS
 * Les clients créés par un Business Owner via "Onboard New Client"
 * peuvent voir leurs invoices à /managed/invoices
 */
@Controller('managed/invoices')
@UseGuards(JwtAuthGuard)
export class ManagedInvoicesController {
  constructor(
    private invoicesService: InvoicesService,
    private flouciService: FlouciService,
  ) {}

  /**
   * Récupère les invoices pour le client MANAGÉ connecté
   * GET /managed/invoices
   * 
   * - Filtre par l'email du client depuis le JWT
   * - Retourne UNIQUEMENT les invoices destinées à ce client
   */
  @Get()
  async getManagedClientInvoices(
    @Req() req: any,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
    @Query('status') status?: string,
  ): Promise<{ success: boolean; invoices?: InvoiceResponseDto[]; total?: number; error?: string }> {
    try {
      // Only CLIENTs can access this endpoint
      if (req.user.role !== 'CLIENT') {
        return { success: false, error: 'Only managed clients can access this endpoint' };
      }

      // Get invoices for this client based on their email
      const clientEmail = req.user.email;
      if (!clientEmail) {
        return { success: false, error: 'Client email not found in token' };
      }

      const result = await this.invoicesService.getInvoicesByClientEmail(
        clientEmail,
        status as any,
        Math.max(1, page),
        Math.max(1, limit),
      );

      return {
        success: true,
        invoices: result.invoices,
        total: result.total,
      };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Récupère une facture unique pour le client MANAGÉ
   * GET /managed/invoices/:id
   */
  @Get(':id')
  async getManagedClientInvoiceById(
    @Req() req: any,
    @Param('id') id: string,
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      if (req.user.role !== 'CLIENT') {
        return { success: false, error: 'Only managed clients can access this endpoint' };
      }

      const clientEmail = req.user.email;
      if (!clientEmail) {
        return { success: false, error: 'Client email not found in token' };
      }

      const result = await this.invoicesService.getInvoiceByClientEmailAndId(id, clientEmail);
      return { success: true, data: result };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Initialiser le paiement Flouci
   * POST /managed/invoices/:id/pay
   */
  @Post(':id/pay')
  async initiatePayment(
    @Req() req: any,
    @Param('id') id: string,
    @Body('successUrl') successUrl: string,
    @Body('failUrl') failUrl: string,
  ): Promise<{ success: boolean; link?: string; error?: string }> {
    try {
      if (req.user.role !== 'CLIENT') {
        return { success: false, error: 'Only managed clients can access this endpoint' };
      }

      const clientEmail = req.user.email;
      if (!clientEmail) {
        return { success: false, error: 'Client email not found in token' };
      }

      // 1. Fetch the invoice to check if it's PENDING and get the amount
      const invoice = await this.invoicesService.getInvoiceByClientEmailAndId(id, clientEmail);
      
      if (invoice.status !== 'PENDING' && invoice.status !== 'SENT' && invoice.status !== 'OVERDUE') {
        return { success: false, error: 'Invoice is not pending payment' };
      }

      // 2. Call FlouciService to generate the payment link
      // invoice.total * 1.19 si TTC n'était pas total? Non, invoice.total est déjà la somme finale.
      const flouciResponse = await this.flouciService.generatePayment(
        invoice.total,
        invoice.id,
        successUrl,
        failUrl,
      );

      return { success: true, link: flouciResponse.link };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Vérifier le paiement Flouci après redirection
   * POST /managed/invoices/:id/verify-payment
   */
  @Post(':id/verify-payment')
  async verifyPayment(
    @Req() req: any,
    @Param('id') id: string,
    @Body('paymentId') paymentId: string,
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      if (req.user.role !== 'CLIENT') {
        return { success: false, error: 'Only managed clients can access this endpoint' };
      }

      const clientEmail = req.user.email;
      if (!clientEmail) {
        return { success: false, error: 'Client email not found in token' };
      }

      // 1. Verify with Flouci
      const flouciVerify = await this.flouciService.verifyPayment(paymentId);
      
      if (flouciVerify.success && flouciVerify.result?.status === 'SUCCESS') {
        // 2. Update Invoice Status to PAID
        const updatedInvoice = await this.invoicesService.markInvoiceAsPaid(id, clientEmail, paymentId);
        return { success: true, data: updatedInvoice };
      } else {
        return { success: false, error: 'Payment was not successful or still pending' };
      }
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }
}
