import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOkResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { Role } from '@/auth/enums/role.enum';
import { InvoicesService } from './invoices.service';
import { InvoiceResponseDto } from './dto/invoice-response.dto';
import { InvoiceStatus } from '@/business/schemas/invoice.schema';

/**
 * Contrôleur pour les invoices des clients RÉGULIERS
 * Les utilisateurs qui se sont inscrits et voient /en/invoices
 * Ils peuvent voir les invoices qui leur sont destinées
 */
@ApiTags('Invoices - Client')
@Controller('invoices/client')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
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
  @ApiOkResponse({
    description: 'Invoices retrieved successfully',
    type: InvoiceResponseDto,
    isArray: true,
  })
  async getMyInvoices(
    @CurrentUser() user: UserPayload,
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('status') status?: InvoiceStatus
  ): Promise<{
    success: boolean;
    invoices?: InvoiceResponseDto[];
    total?: number;
    error?: string;
  }> {
    try {
      // Regular CLIENTs only (not BUSINESS_OWNER)
      if (
        user.role &&
        (user.role === Role.BUSINESS_OWNER || user.role === Role.BUSINESS_ADMIN)
      ) {
        return {
          success: false,
          error:
            'Business owners should use /dashboard/business/invoices instead',
        };
      }

      // Get invoices for this client based on their email
      const clientEmail = user.email;
      if (!clientEmail) {
        return { success: false, error: 'Client email not found in token' };
      }

      const result = await this.invoicesService.getInvoicesByClientEmail(
        clientEmail,
        status,
        Math.max(1, page),
        Math.max(1, limit)
      );

      return {
        success: true,
        invoices: result.invoices,
        total: result.total,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }
}
