import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { InjectModel, InjectConnection } from '@nestjs/mongoose';
import { Model, Connection } from 'mongoose';
import { InvoiceReceipt } from '@/invoices/schemas/invoice-receipt.schema';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import {
  InvoiceReceiptResponseDto,
  InvoiceReceiptListResponseDto,
  InvoiceResponseDto,
} from '@/invoices/dto/invoice.dto';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';

/**
 * InvoiceReceiptService
 * Handles recipient-side invoice discovery and viewing
 * Provides cross-tenant visibility through the platform-level InvoiceReceipt index
 *
 * SECURITY MODEL:
 * - Only PLATFORM_BUSINESS and PLATFORM_INDIVIDUAL recipients can access invoices
 * - EXTERNAL recipients (email-only) cannot access until they claim a platform identity
 * - Email matching is case-insensitive and normalized
 * - Receipts are checked for staleness; issuer's Invoice is authoritative source of truth
 */
@Injectable()
export class InvoiceReceiptService {
  private readonly logger = new Logger(InvoiceReceiptService.name);

  private readonly SYNC_STALENESS_MS = 5 * 60 * 1000; // 5 minutes

  constructor(
    @InjectModel(InvoiceReceipt.name)
    private invoiceReceiptModel: Model<InvoiceReceipt>,
    @InjectModel(Invoice.name) private invoiceModel: Model<Invoice>,
    @InjectConnection() private connection: Connection,
    private tenantConnectionService: TenantConnectionService
  ) {}

  /**
   * Normalize email for consistent matching
   * Lowercase and trim to handle variant email addresses
   */
  private normalizeEmail(email?: string): string | undefined {
    if (!email) return undefined;
    return email.toLowerCase().trim();
  }

  /**
   * Get all invoices received by a business (as recipient)
   * Queries platform-level InvoiceReceipt index
   * Only returns invoices explicitly addressed to this business
   */
  async getReceivedInvoicesByBusiness(
    recipientBusinessId: string,
    page: number,
    limit: number,
    filters?: Record<string, unknown>
  ): Promise<InvoiceReceiptListResponseDto> {
    const skip = (page - 1) * limit;
    const statusFilter =
      filters?.status && typeof filters.status === 'string'
        ? { invoiceStatus: filters.status }
        : {};

    const [receipts, total] = await Promise.all([
      this.invoiceReceiptModel
        .find(Object.assign({ recipientBusinessId }, statusFilter))
        .skip(skip)
        .limit(limit)
        .sort({ issuedDate: -1 })
        .lean({ virtuals: false })
        .exec(),
      this.invoiceReceiptModel.countDocuments(
        Object.assign({ recipientBusinessId }, statusFilter)
      ),
    ]);

    return {
      receipts: receipts.map((receipt) =>
        this.mapReceiptToListResponse(
          receipt as unknown as Record<string, unknown>
        )
      ),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get all invoices received by an individual user
   * Matches by userId (primary) and normalized email (secondary)
   *
   * Email matching is used for invoices created before the user signed up.
   * Once user has a userId, they can access via userId directly.
   */
  async getReceivedInvoicesByIndividual(
    userId: string,
    email: string,
    page: number,
    limit: number,
    filters?: Record<string, unknown>
  ): Promise<InvoiceReceiptListResponseDto> {
    const normalizedEmail = this.normalizeEmail(email);
    const skip = (page - 1) * limit;
    const statusFilter =
      filters?.status && typeof filters.status === 'string'
        ? { invoiceStatus: filters.status }
        : {};

    const [receipts, total] = await Promise.all([
      this.invoiceReceiptModel
        .find(
          Object.assign(
            {
              $or: [
                { recipientUserId: userId },
                { recipientEmail: normalizedEmail },
              ],
            },
            statusFilter
          )
        )
        .skip(skip)
        .limit(limit)
        .sort({ issuedDate: -1 })
        .lean({ virtuals: false })
        .exec(),
      this.invoiceReceiptModel.countDocuments(
        Object.assign(
          {
            $or: [
              { recipientUserId: userId },
              { recipientEmail: normalizedEmail },
            ],
          },
          statusFilter
        )
      ),
    ]);

    return {
      receipts: receipts.map((receipt) =>
        this.mapReceiptToListResponse(
          receipt as unknown as Record<string, unknown>
        )
      ),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get full invoice details as a recipient
   * Requires access to issuer's tenant database to fetch full Invoice
   * Marks receipt as viewed
   *
   * SECURITY CRITICAL:
   * - Only PLATFORM_BUSINESS and PLATFORM_INDIVIDUAL recipients can access
   * - EXTERNAL recipients (email-only) cannot access without claiming platform identity
   * - Cross-tenant reads use TenantConnectionService for isolation
   * - Staleness checks ensure latest invoice state
   */
  async getInvoiceDetailsAsRecipient(
    receiptId: string,
    recipientBusinessId?: string,
    recipientUserId?: string,
    recipientEmail?: string
  ): Promise<InvoiceResponseDto> {
    // Find the receipt
    const receipt = await this.invoiceReceiptModel.findById(receiptId).exec();

    if (!receipt) {
      throw new NotFoundException('Invoice not found');
    }

    // Check staleness: Receipt should be synced recently
    const lastSyncAge = Date.now() - receipt.lastSyncedAt.getTime();
    if (lastSyncAge > this.SYNC_STALENESS_MS) {
      this.logger.warn(
        `Receipt ${receiptId} is stale (${Math.round(lastSyncAge / 1000)}s old). Using cached receipt status.`
      );
    }

    // SECURITY: Verify the recipient has access
    // Critical: External recipients cannot access until they claim platform identity
    let hasAccess = false;

    if (
      recipientBusinessId &&
      receipt.recipientBusinessId?.toString() === recipientBusinessId
    ) {
      hasAccess = true;
    } else if (
      recipientUserId &&
      receipt.recipientUserId?.toString() === recipientUserId
    ) {
      hasAccess = true;
    } else if (recipientEmail) {
      const normalizedEmail = this.normalizeEmail(recipientEmail);
      const receiptNormalizedEmail = this.normalizeEmail(
        receipt.recipientEmail
      );

      // Allow access ONLY if:
      // 1. Email matches AND
      // 2. Receipt has a userId (was resolved from external) OR has a businessId
      // This prevents external/unresolved recipients from accessing
      if (
        normalizedEmail &&
        normalizedEmail === receiptNormalizedEmail &&
        (receipt.recipientUserId || receipt.recipientBusinessId)
      ) {
        hasAccess = true;
      } else if (
        normalizedEmail &&
        normalizedEmail === receiptNormalizedEmail &&
        receipt.recipientUserId === undefined &&
        receipt.recipientBusinessId === undefined
      ) {
        // DENY: External recipient (email-only) without platform identity
        this.logger.warn(
          `External recipient ${recipientEmail} attempted direct access to unresolved invoice ${receiptId}`
        );
        throw new ForbiddenException(
          'External recipients must verify their email and create a platform account before accessing invoices.'
        );
      }
    }

    if (!hasAccess) {
      throw new ForbiddenException('You do not have access to this invoice');
    }

    // Fetch the full invoice from issuer's tenant database
    let invoice: Invoice | null;

    try {
      // Use TenantConnectionService to safely access issuer's isolated database
      // This prevents cross-tenant data leakage
      if (receipt.issuerTenantDatabaseName) {
        const issuerInvoiceModel =
          this.tenantConnectionService.getTenantModel<Invoice>({
            databaseName: receipt.issuerTenantDatabaseName,
            modelName: 'Invoice',
            schema: InvoiceSchema,
          });
        invoice = await issuerInvoiceModel.findById(receipt.invoiceId).exec();
      } else {
        // Fallback to platform Invoice collection if tenant DB not set
        invoice = await this.invoiceModel.findById(receipt.invoiceId).exec();
      }
    } catch (error) {
      this.logger.error(
        `Failed to fetch invoice ${receipt.invoiceId} from issuer ${receipt.issuerTenantDatabaseName}: ${error}`
      );
      throw new NotFoundException(
        'Invoice not found in issuer database (sync failure)'
      );
    }

    if (invoice === null || invoice === undefined) {
      throw new NotFoundException(
        'Invoice has been deleted or is no longer available'
      );
    }

    // Mark receipt as viewed (non-blocking)
    if (!receipt.recipientViewed) {
      await this.invoiceReceiptModel
        .updateOne(
          { _id: receiptId },
          {
            recipientViewed: true,
            recipientViewedAt: new Date(),
          }
        )
        .catch((error) => {
          this.logger.error(`Failed to mark receipt as viewed: ${error}`);
        });
    }

    return this.mapInvoiceToResponse(invoice);
  }

  /**
   * Map InvoiceReceipt to list response (summary view)
   */
  private mapReceiptToListResponse(
    receipt: Record<string, unknown>
  ): InvoiceReceiptResponseDto {
    const receiptId = receipt._id;
    const invoiceId = receipt.invoiceId;
    const issuerBusinessId = receipt.issuerBusinessId;
    const issuerTenantDatabaseName = receipt.issuerTenantDatabaseName as string;
    const issuerBusinessName = receipt.issuerBusinessName as string;
    const invoiceNumber = receipt.invoiceNumber as string;
    const totalAmount = receipt.totalAmount as number;
    const currency = receipt.currency as string;
    const createdAt = receipt.createdAt as Date;

    const id =
      receiptId && typeof receiptId === 'object' && 'toString' in receiptId
        ? (receiptId as { toString(): string }).toString()
        : String(receiptId);
    const invId =
      invoiceId && typeof invoiceId === 'object' && 'toString' in invoiceId
        ? (invoiceId as { toString(): string }).toString()
        : String(invoiceId);
    const issuerBizIdStr =
      issuerBusinessId &&
      typeof issuerBusinessId === 'object' &&
      'toString' in issuerBusinessId
        ? (issuerBusinessId as { toString(): string }).toString()
        : String(issuerBusinessId);

    const invoiceStatusStr =
      typeof receipt.invoiceStatus === 'string'
        ? (receipt.invoiceStatus as InvoiceStatus)
        : (InvoiceStatus.DRAFT as InvoiceStatus);
    const createdAtDate = createdAt instanceof Date ? createdAt : new Date();

    return {
      id,
      invoiceId: invId,
      issuerTenantDatabaseName,
      issuerBusinessId: issuerBizIdStr,
      issuerBusinessName,
      invoiceNumber,
      totalAmount,
      currency,
      issuedDate: receipt.issuedDate as Date,
      dueDate: receipt.dueDate as Date,
      invoiceStatus: invoiceStatusStr,
      recipientViewed: receipt.recipientViewed as boolean,
      recipientViewedAt: receipt.recipientViewedAt as Date | undefined,
      lastSyncedAt: receipt.lastSyncedAt as Date,
      createdAt: createdAtDate,
    };
  }

  /**
   * Safely extract and convert ObjectId to string
   */
  private objectIdToString(value: unknown): string {
    if (typeof value === 'string') {
      return value;
    }
    if (value && typeof value === 'object' && 'toString' in value) {
      return (value as { toString(): string }).toString();
    }
    return String(value);
  }

  /**
   * Map Invoice document to response DTO
   * Uses Invoice as source of truth (not receipt cached values)
   */
  private mapInvoiceToResponse(invoice: Invoice): InvoiceResponseDto {
    const id = this.objectIdToString(invoice._id);
    const issuerBizId = this.objectIdToString(invoice.issuerBusinessId);
    const createdByStr = this.objectIdToString(invoice.createdBy);
    const lastModifiedByStr = this.objectIdToString(invoice.lastModifiedBy);

    return {
      id,
      issuerBusinessId: issuerBizId,
      invoiceNumber: invoice.invoiceNumber,
      recipient: {
        type: invoice.recipient.type,
        platformId: invoice.recipient.platformId?.toString(),
        tenantDatabaseName: invoice.recipient.tenantDatabaseName,
        email: invoice.recipient.email,
        displayName: invoice.recipient.displayName,
        resolutionStatus: invoice.recipient.resolutionStatus,
        lastResolutionAttempt: invoice.recipient.lastResolutionAttempt,
      },
      status: invoice.status,
      totalAmount: invoice.totalAmount,
      currency: invoice.currency,
      amountPaid: invoice.amountPaid,
      issuedDate: invoice.issuedDate,
      dueDate: invoice.dueDate,
      lineItems: invoice.lineItems.map((item) => ({
        id: this.objectIdToString(item._id),
        productId: this.objectIdToString(item.productId),
        productName: item.productName,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        amount: item.amount,
        description: item.description,
      })),
      description: invoice.description,
      paymentTerms: invoice.paymentTerms,
      voidReason: invoice.voidReason,
      voidedAt: invoice.voidedAt,
      createdBy: createdByStr,
      lastModifiedBy: lastModifiedByStr,
      lastStatusChangeAt: invoice.lastStatusChangeAt,
      createdAt: invoice.createdAt,
      updatedAt: invoice.updatedAt,
    };
  }
}
