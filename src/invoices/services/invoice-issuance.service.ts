import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { InjectModel, InjectConnection } from '@nestjs/mongoose';
import { Model, Connection } from 'mongoose';
import {
  CreateInvoiceDto,
  UpdateInvoiceDto,
  TransitionInvoiceStateDto,
  InvoiceResponseDto,
  InvoiceListResponseDto,
} from '@/invoices/dto/invoice.dto';
import { Invoice } from '@/invoices/schemas/invoice.schema';
import { InvoiceReceipt } from '@/invoices/schemas/invoice-receipt.schema';
import {
  InvoiceStatus,
  INVOICE_STATUS_TRANSITIONS,
} from '@/invoices/enums/invoice-status.enum';
import {
  InvoiceRecipientType,
  RecipientResolutionStatus,
} from '@/invoices/enums/invoice-recipient.enum';
import { Business } from '@/business/schemas/business.schema';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';

/**
 * InvoiceIssuanceService
 * Handles creation, management, and lifecycle of invoices issued by a business
 * Source of truth for all invoice content and state
 *
 * ARCHITECTURAL PROPERTIES:
 * - Invoices live in issuer's tenant database (authoritative source)
 * - InvoiceReceipts synced to platform DB for cross-tenant discoverability
 * - All recipient emails normalized (lowercase) for consistency
 * - Sync failures are logged but non-blocking (eventual consistency)
 * - Invoice status on issuer side is always authoritative
 */
@Injectable()
export class InvoiceIssuanceService {
  private readonly logger = new Logger(InvoiceIssuanceService.name);

  constructor(
    @InjectModel(Invoice.name) private invoiceModel: Model<Invoice>,
    @InjectModel(InvoiceReceipt.name)
    private invoiceReceiptModel: Model<InvoiceReceipt>,
    @InjectModel(Business.name) private businessModel: Model<Business>,
    @InjectConnection() private connection: Connection,
    private tenantConnectionService: TenantConnectionService
  ) {}

  /**
   * Normalize email for consistent recipient matching
   * Handles variant email addresses: different cases, whitespace
   */
  private normalizeEmail(email?: string): string | undefined {
    if (!email) return undefined;
    return email.toLowerCase().trim();
  }

  /**
   * Create a new draft invoice in the issuer's tenant database
   * Invoice is private until transitioned to ISSUED state
   */
  async createDraftInvoice(
    businessId: string,
    databaseName: string,
    dto: CreateInvoiceDto,
    userId: string
  ): Promise<InvoiceResponseDto> {
    // Calculate total amount from line items
    const totalAmount = dto.lineItems.reduce(
      (sum, item) => sum + item.quantity * item.unitPrice,
      0
    );

    // Create line items with amounts
    const lineItems = dto.lineItems.map((item) => ({
      productId: item.productId,
      productName: item.productName,
      quantity: item.quantity,
      unitPrice: item.unitPrice,
      amount: item.quantity * item.unitPrice,
      description: item.description,
    }));

    // Auto-generate invoiceNumber if not provided
    // Format: INV-{YYYYMMDD}-{randomString}
    // Example: INV-20250404-k7x9m2
    let invoiceNumber = dto.invoiceNumber;
    if (!invoiceNumber) {
      const now = new Date();
      const dateStr = now.toISOString().slice(0, 10).replaceAll('-', ''); // YYYYMMDD
      const randomStr = Math.random().toString(36).slice(2, 8).toUpperCase(); // 6-char random string
      invoiceNumber = `INV-${dateStr}-${randomStr}`;
    }

    // Normalize recipient email for consistent matching
    const normalizedEmail = this.normalizeEmail(dto.recipient.email);

    // Determine resolution status based on recipient type
    // EXTERNAL recipients are PENDING until they claim platform identity
    // PLATFORM_BUSINESS and PLATFORM_INDIVIDUAL are already RESOLVED
    let resolutionStatus = RecipientResolutionStatus.RESOLVED;
    if (dto.recipient.type === InvoiceRecipientType.EXTERNAL) {
      resolutionStatus = RecipientResolutionStatus.PENDING;
    }

    // Create invoice in draft state
    const invoice = await this.invoiceModel.create({
      issuerBusinessId: businessId,
      invoiceNumber,
      recipient: {
        type: dto.recipient.type,
        platformId: dto.recipient.platformId,
        email: normalizedEmail,
        displayName: dto.recipient.displayName,
        resolutionStatus,
      },
      status: InvoiceStatus.DRAFT,
      totalAmount,
      currency: dto.currency ?? 'TND',
      amountPaid: 0,
      issuedDate: dto.issuedDate,
      dueDate: dto.dueDate,
      lineItems,
      description: dto.description,
      paymentTerms: dto.paymentTerms,
      createdBy: userId,
      lastModifiedBy: userId,
      lastStatusChangeAt: new Date(),
    } as Partial<Invoice>);

    this.logger.debug(
      `Created draft invoice ${invoice._id.toString()} for business ${businessId}`
    );

    return this.mapInvoiceToResponse(invoice);
  }

  /**
   * Get all invoices issued by a business, with optional filtering
   */
  async getIssuerInvoices(
    businessId: string,
    page: number,
    limit: number,
    filters?: Record<string, unknown>
  ): Promise<InvoiceListResponseDto> {
    const skip = (page - 1) * limit;
    const statusFilter =
      filters?.status && typeof filters.status === 'string'
        ? { status: filters.status }
        : {};

    const [invoices, total] = await Promise.all([
      this.invoiceModel
        .find(Object.assign({ issuerBusinessId: businessId }, statusFilter))
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 })
        .exec(),
      this.invoiceModel.countDocuments(
        Object.assign({ issuerBusinessId: businessId }, statusFilter)
      ),
    ]);

    return {
      invoices: invoices.map((inv) => this.mapInvoiceToResponse(inv)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get a specific invoice by ID
   */
  async getInvoiceById(invoiceId: string): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(invoiceId).exec();
    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }
    return this.mapInvoiceToResponse(invoice);
  }

  /**
   * Update a draft invoice (only DRAFT invoices can be edited)
   */
  async updateDraftInvoice(
    invoiceId: string,
    businessId: string,
    dto: UpdateInvoiceDto,
    userId: string
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(invoiceId).exec();

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.issuerBusinessId.toString() !== businessId) {
      throw new ForbiddenException('You do not own this invoice');
    }

    if (invoice.status !== InvoiceStatus.DRAFT) {
      throw new BadRequestException(
        'Only draft invoices can be edited. Use state transitions for other changes.'
      );
    }

    invoice.description = dto.description ?? invoice.description;
    invoice.paymentTerms = dto.paymentTerms ?? invoice.paymentTerms;
    invoice.dueDate = dto.dueDate ?? invoice.dueDate;
    invoice.lastModifiedBy = userId;

    await invoice.save();

    this.logger.debug(
      `Updated draft invoice ${invoiceId} for business ${businessId}`
    );

    return this.mapInvoiceToResponse(invoice);
  }

  /**
   * Transition invoice to a new state (validate state machine)
   */
  async transitionInvoiceState(
    invoiceId: string,
    businessId: string,
    databaseName: string,
    dto: TransitionInvoiceStateDto,
    userId: string
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(invoiceId).exec();

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.issuerBusinessId.toString() !== businessId) {
      throw new ForbiddenException('You do not own this invoice');
    }

    // Validate state transition using state machine
    const validTransitions = INVOICE_STATUS_TRANSITIONS[invoice.status];
    if (!validTransitions.includes(dto.newStatus)) {
      throw new BadRequestException(
        `Cannot transition from ${invoice.status} to ${dto.newStatus}`
      );
    }

    // Update payment if transitioning to PAID/PARTIAL
    if (
      dto.newStatus === InvoiceStatus.PAID ||
      dto.newStatus === InvoiceStatus.PARTIAL
    ) {
      if (dto.amountPaid === undefined) {
        throw new BadRequestException(
          'amountPaid is required for payment states'
        );
      }
      invoice.amountPaid = dto.amountPaid;
      invoice.paymentDates = invoice.paymentDates ?? [];
      invoice.paymentDates.push(new Date());
    }

    // Update status and audit fields
    const previousStatus = invoice.status;
    invoice.status = dto.newStatus;
    invoice.lastStatusChangeAt = new Date();
    invoice.lastModifiedBy = userId;

    // Handle voiding
    if (dto.newStatus === InvoiceStatus.VOIDED) {
      invoice.voidReason = dto.reason;
      invoice.voidedAt = new Date();
    }

    await invoice.save();

    this.logger.log(
      `Invoice ${invoiceId} transitioned from ${previousStatus} to ${dto.newStatus}`
    );

    // Sync receipt to platform DB if invoice is now ISSUED
    // This makes it visible to recipients
    if (dto.newStatus === InvoiceStatus.ISSUED) {
      await this.syncInvoiceToReceipt(invoice, databaseName);
    } else if (
      invoice.status !== InvoiceStatus.DRAFT &&
      [
        InvoiceStatus.PAID,
        InvoiceStatus.VOIDED,
        InvoiceStatus.ARCHIVED,
      ].includes(invoice.status)
    ) {
      // Update receipt for financial state changes
      await this.updateReceiptFromInvoice(invoice);
    }

    return this.mapInvoiceToResponse(invoice);
  }

  /**
   * Create or update an InvoiceReceipt to make invoice visible to recipients
   * Called when invoice transitions to ISSUED
   *
   * This is the critical cross-tenant sync point:
   * - Receipt is created in platform DB for recipient discoverability
   * - Receipt contains metadata but not full financial details
   * - Recipient queries receipt to find invoice, then fetches from issuer's tenant
   *
   * CONSISTENCY: Failures are logged but non-blocking (eventual consistency model)
   */
  private async syncInvoiceToReceipt(
    invoice: Invoice,
    databaseName: string
  ): Promise<void> {
    try {
      // Fetch business name for receipt
      const business = await this.businessModel.findById(
        invoice.issuerBusinessId
      );
      const issuerBusinessName = business?.name ?? 'Unknown Business';

      // Check if receipt already exists (idempotent)
      const existingReceipt = await this.invoiceReceiptModel
        .findOne({
          invoiceId: invoice._id.toString(),
        })
        .exec();

      const receiptData: Record<string, unknown> = {
        invoiceId: invoice._id.toString(),
        issuerTenantDatabaseName: databaseName,
        issuerBusinessId: invoice.issuerBusinessId,
        issuerBusinessName,
        invoiceNumber: invoice.invoiceNumber,
        totalAmount: invoice.totalAmount,
        currency: invoice.currency,
        issuedDate: invoice.issuedDate,
        dueDate: invoice.dueDate,
        invoiceStatus: invoice.status,
        recipientViewed: false,
        lastSyncedAt: new Date(),
      };

      // Populate recipient-specific lookup fields based on recipient type
      if (invoice.recipient.type === InvoiceRecipientType.PLATFORM_BUSINESS) {
        receiptData.recipientBusinessId = invoice.recipient.platformId;
      } else if (
        invoice.recipient.type === InvoiceRecipientType.PLATFORM_INDIVIDUAL
      ) {
        receiptData.recipientUserId = invoice.recipient.platformId;
        receiptData.recipientEmail = invoice.recipient.email;
      } else {
        // EXTERNAL: email-only recipient
        receiptData.recipientEmail = invoice.recipient.email;
        receiptData.recipientDisplayName = invoice.recipient.displayName;
      }

      if (existingReceipt) {
        await this.invoiceReceiptModel.updateOne(
          { _id: existingReceipt._id },
          receiptData
        );
        this.logger.debug(
          `Updated InvoiceReceipt ${existingReceipt._id.toString()}`
        );
      } else {
        const created = await this.invoiceReceiptModel.create(receiptData);
        this.logger.log(
          `Created InvoiceReceipt ${created._id.toString()} for invoice ${invoice._id.toString()}`
        );
      }
    } catch (error) {
      // Non-blocking: Log but don't fail the invoice transition
      // Eventual consistency: Receipt will be re-synced on next status change
      this.logger.error(
        `Failed to sync InvoiceReceipt for ${invoice._id.toString()}: ${error}`,
        error
      );
    }
  }

  /**
   * Update an existing InvoiceReceipt when invoice state changes
   * Used for PAID, VOIDED, ARCHIVED transitions
   */
  private async updateReceiptFromInvoice(invoice: Invoice): Promise<void> {
    try {
      await this.invoiceReceiptModel.updateOne(
        { invoiceId: invoice._id.toString() },
        {
          invoiceStatus: invoice.status,
          lastSyncedAt: new Date(),
        }
      );
      this.logger.debug(
        `Updated InvoiceReceipt status for ${invoice._id.toString()}`
      );
    } catch (error) {
      // Non-blocking
      this.logger.warn(
        `Failed to update InvoiceReceipt status for ${invoice._id.toString()}: ${error}`
      );
    }
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
