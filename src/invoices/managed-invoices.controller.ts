import {
  Controller,
  Get,
  Query,
  UseGuards,
  Param,
  Post,
  Body,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { Role } from '@/auth/enums/role.enum';
import { InvoicesService } from './invoices.service';
import { FlouciService } from './flouci.service';
import { InvoiceResponseDto } from './dto/invoice-response.dto';
import { InvoiceStatus } from '@/invoices/schemas/invoice.schema';

/**
 * Contrôleur pour les invoices des clients MANAGÉS
 * Les clients créés par un Business Owner via "Onboard New Client"
 * peuvent voir leurs invoices à /managed/invoices
 */
@ApiTags('Invoices - Managed')
@Controller('managed/invoices')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class ManagedInvoicesController {
  constructor(
    private invoicesService: InvoicesService,
    private flouciService: FlouciService
  ) {}

  /**
   * Récupère les invoices pour le client MANAGÉ connecté
   * GET /managed/invoices
   *
   * - Filtre par l'email du client depuis le JWT
   * - Retourne UNIQUEMENT les invoices destinées à ce client
   */
  @Get()
  @ApiOkResponse({
    description: 'List of managed client invoices retrieved successfully',
    type: [InvoiceResponseDto],
  })
  async getManagedClientInvoices(
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
      // Only CLIENTs can access this endpoint
      if (user.role !== Role.CLIENT) {
        return {
          success: false,
          error: 'Only managed clients can access this endpoint',
        };
      }

      // Get invoices for this user by their ID
      const result = await this.invoicesService.getInvoicesByUserId(
        user.id,
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

  /**
   * Récupère une facture unique pour le client MANAGÉ
   * GET /managed/invoices/:id
   */
  @Get(':id')
  @ApiOkResponse({
    description: 'Managed client invoice retrieved successfully',
    type: InvoiceResponseDto,
  })
  async getManagedClientInvoiceById(
    @CurrentUser() user: UserPayload,
    @Param('id') id: string
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      if (user.role !== Role.CLIENT) {
        return {
          success: false,
          error: 'Only managed clients can access this endpoint',
        };
      }

      const result = await this.invoicesService.getInvoiceByInvoiceId(id);
      return { success: true, data: result };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }

  /**
   * Initialiser le paiement Flouci
   * POST /managed/invoices/:id/pay
   */
  @Post(':id/pay')
  @ApiCreatedResponse({
    description: 'Payment initiated successfully',
    schema: {
      properties: {
        success: { type: 'boolean' },
        link: { type: 'string' },
        error: { type: 'string' },
      },
    },
  })
  async initiatePayment(
    @CurrentUser() user: UserPayload,
    @Param('id') id: string,
    @Body('successUrl') successUrl: string,
    @Body('failUrl') failUrl: string
  ): Promise<{ success: boolean; link?: string; error?: string }> {
    try {
      if (user.role !== Role.CLIENT) {
        return {
          success: false,
          error: 'Only managed clients can access this endpoint',
        };
      }

      // 1. Fetch the invoice to check if it's PENDING and get the amount
      const invoice = await this.invoicesService.getInvoiceByInvoiceId(id);

      if (
        (invoice.status as unknown as InvoiceStatus) !==
          InvoiceStatus.PENDING &&
        (invoice.status as unknown as InvoiceStatus) !== InvoiceStatus.SENT &&
        (invoice.status as unknown as InvoiceStatus) !== InvoiceStatus.OVERDUE
      ) {
        return { success: false, error: 'Invoice is not pending payment' };
      }

      // 2. Call FlouciService to generate the payment link
      // invoice.total * 1.19 si TTC n'était pas total? Non, invoice.total est déjà la somme finale.
      const flouciResponse = await this.flouciService.generatePayment(
        invoice.total,
        invoice.id,
        successUrl,
        failUrl
      );

      return { success: true, link: flouciResponse.link };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }

  /**
   * Vérifier le paiement Flouci après redirection
   * POST /managed/invoices/:id/verify-payment
   */
  @Post(':id/verify-payment')
  @ApiOkResponse({
    description: 'Payment verified successfully',
    type: InvoiceResponseDto,
  })
  async verifyPayment(
    @CurrentUser() user: UserPayload,
    @Param('id') id: string,
    @Body('paymentId') paymentId: string
  ): Promise<{ success: boolean; data?: InvoiceResponseDto; error?: string }> {
    try {
      if (user.role !== Role.CLIENT) {
        return {
          success: false,
          error: 'Only managed clients can access this endpoint',
        };
      }

      const clientEmail = user.email;
      if (!clientEmail) {
        return { success: false, error: 'Client email not found in token' };
      }

      // 1. Verify with Flouci
      const flouciVerify = await this.flouciService.verifyPayment(paymentId);

      if (flouciVerify.success && flouciVerify.result?.status === 'SUCCESS') {
        // 2. Update Invoice Status to PAID
        const updatedInvoice = await this.invoicesService.markInvoiceAsPaid(
          id,
          clientEmail,
          paymentId
        );
        return { success: true, data: updatedInvoice };
      } else {
        return {
          success: false,
          error: 'Payment was not successful or still pending',
        };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: message };
    }
  }
}
