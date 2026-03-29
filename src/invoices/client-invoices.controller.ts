import {
  Controller,
  Get,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { InvoicesService } from './invoices.service';
import { InvoiceResponseDto } from './dto/invoice-response.dto';

/**
 * Contrôleur pour les invoices des clients RÉGULIERS
 * Les utilisateurs qui se sont inscrits et voient /en/invoices
 * Ils peuvent voir les invoices qui leur sont destinées
 */
@Controller('invoices/client')
@UseGuards(JwtAuthGuard)
export class ClientInvoicesController {
  constructor(private invoicesService: InvoicesService) {}

  /**
   * Récupère les invoices pour le client RÉGULIER connecté
   * GET /invoices/client/my
   * 
   * - Filtre par l'email du client depuis le JWT
   * - Retourne UNIQUEMENT les invoices destinées à ce client
   */
  @Get('my')
  async getMyInvoices(
    @Req() req: any,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
    @Query('status') status?: string,
  ): Promise<{ success: boolean; invoices?: InvoiceResponseDto[]; total?: number; error?: string }> {
    try {
      // Regular CLIENTs only (not BUSINESS_OWNER)
      if (req.user.role && (req.user.role === 'BUSINESS_OWNER' || req.user.role === 'BUSINESS_ADMIN')) {
        return { success: false, error: 'Business owners should use /dashboard/business/invoices instead' };
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
}
