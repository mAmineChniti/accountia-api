import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { InjectModel, InjectConnection } from '@nestjs/mongoose';
import { Model, Connection } from 'mongoose';
import { ObjectId } from 'mongodb';
import {
  CreateInvoiceDto,
  UpdateInvoiceDto,
  TransitionInvoiceStateDto,
  InvoiceResponseDto,
  InvoiceListResponseDto,
} from '@/invoices/dto/invoice.dto';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
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
import { NotificationsService } from '@/notifications/notifications.service';
import { NotificationType } from '@/notifications/schemas/notification.schema';

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

  private readonly statusAliasMap: Record<string, InvoiceStatus> = {
    DRAFT: InvoiceStatus.DRAFT,
    ISSUED: InvoiceStatus.ISSUED,
    VIEWED: InvoiceStatus.VIEWED,
    PAID: InvoiceStatus.PAID,
    PARTIAL: InvoiceStatus.PARTIAL,
    OVERDUE: InvoiceStatus.OVERDUE,
    DISPUTED: InvoiceStatus.DISPUTED,
    VOIDED: InvoiceStatus.VOIDED,
    ARCHIVED: InvoiceStatus.ARCHIVED,
  };

  constructor(
    @InjectModel(InvoiceReceipt.name)
    private invoiceReceiptModel: Model<InvoiceReceipt>,
    @InjectModel(Business.name) private businessModel: Model<Business>,
    @InjectConnection() private connection: Connection,
    private tenantConnectionService: TenantConnectionService,
    private notificationsService: NotificationsService
  ) {}

  /**
   * Normalize email for consistent recipient matching
   * Handles variant email addresses: different cases, whitespace
   */
  private normalizeEmail(email?: string): string | undefined {
    if (!email) return undefined;
    return email.toLowerCase().trim();
  }

  private normalizeInvoiceStatus(value: unknown): InvoiceStatus {
    const raw = typeof value === 'string' ? value.trim().toUpperCase() : '';
    const normalized = this.statusAliasMap[raw];
    if (!normalized) {
      throw new BadRequestException(
        `Unsupported invoice status: ${String(value)}`
      );
    }
    return normalized;
  }

  /**
   * Convert empty string values to undefined to avoid ObjectId cast failures.
   */
  private normalizeOptionalString(value?: string): string | undefined {
    if (typeof value !== 'string') {
      return undefined;
    }

    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  /**
   * Accept only valid Mongo ObjectId values for audit user fields.
   * This prevents runtime cast errors when payment callbacks run without a user context.
   */
  private normalizeAuditUserId(userId?: string): string | undefined {
    const normalized = this.normalizeOptionalString(userId);
    if (!normalized) {
      return undefined;
    }

    return ObjectId.isValid(normalized) ? normalized : undefined;
  }

  private getTenantInvoiceModel(databaseName: string): Model<Invoice> {
    return this.tenantConnectionService.getTenantModel<Invoice>({
      databaseName,
      modelName: Invoice.name,
      schema: InvoiceSchema,
      collectionName: 'invoices',
    });
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
    const invoiceModel = this.getTenantInvoiceModel(databaseName);

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
    const normalizedPlatformId = this.normalizeOptionalString(
      dto.recipient.platformId
    );

    // Determine resolution status based on recipient type
    // EXTERNAL recipients are PENDING until they claim platform identity
    // PLATFORM_BUSINESS and PLATFORM_INDIVIDUAL are already RESOLVED
    let resolutionStatus = RecipientResolutionStatus.RESOLVED;
    if (dto.recipient.type === InvoiceRecipientType.EXTERNAL) {
      resolutionStatus = RecipientResolutionStatus.PENDING;
    }

    const reservedProducts: Array<{ productId: ObjectId; quantity: number }> =
      [];

    try {
      // Reserve product quantities FIRST — this also resolves product names → real ObjectIds
      // by mutating dto.lineItems[i].productId in-place.
      await this.reserveProductQuantities(
        businessId,
        databaseName,
        dto.lineItems,
        reservedProducts
      );

      // Build lineItems AFTER reservation so resolved ObjectIds are used in the invoice document.
      const totalAmount = dto.lineItems.reduce(
        (sum, item) => sum + item.quantity * item.unitPrice,
        0
      );

      const lineItems = dto.lineItems.map((item) => ({
        productId: item.productId,
        productName: item.productName,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        amount: item.quantity * item.unitPrice,
        description: item.description,
      }));

      // Create invoice in draft state in tenant database
      // Note: Mongoose will auto-convert businessId string to ObjectId in MongoDB
      const invoice = await invoiceModel.create({
        issuerBusinessId: businessId,
        invoiceNumber,
        recipient: {
          type: dto.recipient.type,
          platformId: normalizedPlatformId,
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
        `Created draft invoice ${invoice._id.toString()} for business ${businessId} in tenant database: ${databaseName}`
      );

      // Also save to platform database for cross-tenant visibility and archival
      try {
        await this.saveToPlatformDatabase(invoice, databaseName);
        this.logger.debug(
          `Synchronized invoice ${invoice._id.toString()} to platform database`
        );
      } catch (error) {
        // Non-blocking: Log but don't fail the invoice creation
        this.logger.warn(
          `Failed to sync invoice ${invoice._id.toString()} to platform database: ${error}`,
          error
        );
      }

      return this.mapInvoiceToResponse(invoice);
    } catch (error) {
      await this.rollbackReservedQuantities(databaseName, reservedProducts);
      throw error;
    }
  }

  /**
   * Resolve a productId or product name to a MongoDB ObjectId.
   * If the value is already a valid ObjectId string, it is used directly.
   * Otherwise, it is treated as a product name and looked up in the tenant DB.
   * Returns the resolved ObjectId string, or throws if not found.
   */
  private async resolveProductId(
    productIdOrName: string,
    businessId: string,
    databaseName: string
  ): Promise<string> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    const productsCollection = tenantDb.collection('products');
    const businessObjectId = new ObjectId(businessId);

    // If it looks like an ObjectId, verify it actually exists in the database
    if (ObjectId.isValid(productIdOrName)) {
      const objectId = new ObjectId(productIdOrName);
      const productById = await productsCollection.findOne({
        _id: objectId,
        $or: [{ businessId: businessObjectId }, { businessId }],
      });
      if (productById) {
        return productById._id.toString();
      }
      // If not found by ID, continue to name-based lookup (product name might be 24-char hex)
    }

    // Treat as product name — look up by exact name (case-insensitive)

    const product = await productsCollection.findOne({
      name: {
        $regex: `^${productIdOrName.replaceAll(/[$()*+.?[\\\]^{|}]/g, String.raw`\$&`)}$`,
        $options: 'i',
      },
      $or: [{ businessId: businessObjectId }, { businessId }],
    });

    if (!product) {
      throw new NotFoundException(
        `Product "${productIdOrName}" not found for this business. ` +
          `Please use a valid product name or MongoDB ObjectId.`
      );
    }

    return product._id.toString();
  }

  private async reserveProductQuantities(
    businessId: string,
    databaseName: string,
    lineItems: CreateInvoiceDto['lineItems'],
    reservedProducts: Array<{ productId: ObjectId; quantity: number }>
  ): Promise<void> {
    if (lineItems.length === 0) {
      return;
    }

    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    const productsCollection = tenantDb.collection('products');
    const businessObjectId = new ObjectId(businessId);

    // Resolve all productIds (supports both ObjectId strings and product names)
    const quantitiesByProduct = new Map<string, number>();
    for (const item of lineItems) {
      const rawId = this.normalizeOptionalString(item.productId);
      if (!rawId) {
        throw new BadRequestException(`Missing productId in line items`);
      }

      // Resolve name → ObjectId if needed
      const resolvedId = await this.resolveProductId(
        rawId,
        businessId,
        databaseName
      );

      quantitiesByProduct.set(
        resolvedId,
        (quantitiesByProduct.get(resolvedId) ?? 0) + item.quantity
      );

      // Mutate the lineItem so the invoice document stores the real ObjectId
      item.productId = resolvedId;
    }

    for (const [
      productId,
      quantityToReserve,
    ] of quantitiesByProduct.entries()) {
      const productObjectId = new ObjectId(productId);
      const updateResult = await productsCollection.updateOne(
        {
          _id: productObjectId,
          $or: [{ businessId: businessObjectId }, { businessId }],
          quantity: { $gte: quantityToReserve },
        },
        { $inc: { quantity: -quantityToReserve } }
      );

      if (updateResult.modifiedCount !== 1) {
        const product = await productsCollection.findOne({
          _id: productObjectId,
          $or: [{ businessId: businessObjectId }, { businessId }],
        });

        if (!product) {
          throw new NotFoundException(
            `Product ${productId} not found for this business`
          );
        }

        const currentQuantity =
          typeof product.quantity === 'number' ? product.quantity : 0;
        throw new BadRequestException(
          `Insufficient quantity for product "${product.name ?? productId}". Available: ${currentQuantity}, required: ${quantityToReserve}`
        );
      }

      reservedProducts.push({
        productId: productObjectId,
        quantity: quantityToReserve,
      });
    }
  }

  private async rollbackReservedQuantities(
    databaseName: string,
    reservedProducts: Array<{ productId: ObjectId; quantity: number }>
  ): Promise<void> {
    if (reservedProducts.length === 0) {
      return;
    }

    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    const productsCollection = tenantDb.collection('products');

    for (const reserved of reservedProducts) {
      try {
        await productsCollection.updateOne(
          { _id: reserved.productId },
          { $inc: { quantity: reserved.quantity } }
        );
      } catch (rollbackError) {
        this.logger.error(
          `Failed to rollback quantity for product ${reserved.productId.toString()}`,
          rollbackError as Error
        );
      }
    }
  }

  /**
   * Get all invoices issued by a business, with optional filtering
   *
   * TENANT DB ISOLATION:
   * - Uses tenant-scoped invoice model via tenantConnectionService
   * - Ensures data is retrieved from issuer's tenant database only
   * - Never crosses tenant boundaries
   *
   * PAGINATION:
   * - `total`: Actual count of all invoices for this business (unfiltered)
   * - `filteredTotal`: Count of invoices matching applied filters
   * - This allows clients to show: "Showing X of Y total invoices"
   */
  async getIssuerInvoices(
    businessId: string,
    databaseName: string,
    page: number,
    limit: number,
    filters?: Record<string, unknown>
  ): Promise<InvoiceListResponseDto> {
    const skip = (page - 1) * limit;
    const statusFilter =
      filters?.status && typeof filters.status === 'string'
        ? { status: filters.status }
        : {};

    // Get tenant-scoped invoice model for proper multi-tenancy isolation
    const invoiceModel = this.getTenantInvoiceModel(databaseName);

    // Fetch in parallel: actual total, filtered invoices, and filtered count
    const [total, invoices, filteredTotal] = await Promise.all([
      // Get ACTUAL TOTAL of all invoices for this business (unfiltered)
      invoiceModel.countDocuments({
        issuerBusinessId: businessId,
      }),
      // Get filtered and paginated invoices from tenant database
      invoiceModel
        .find(Object.assign({ issuerBusinessId: businessId }, statusFilter))
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 })
        .exec(),
      // Get count of filtered results (for display purposes)
      invoiceModel.countDocuments(
        Object.assign({ issuerBusinessId: businessId }, statusFilter)
      ),
    ]);

    return {
      invoices: invoices.map((inv) => this.mapInvoiceToResponse(inv)),
      total, // Actual total of all invoices for this business
      filteredTotal, // Count of invoices matching the applied filter
      page,
      limit,
      totalPages: Math.ceil(filteredTotal / limit), // Pagination based on filtered results
    };
  }

  /**
   * Get a specific invoice by ID
   */
  async getInvoiceById(
    invoiceId: string,
    databaseName: string
  ): Promise<InvoiceResponseDto> {
    const invoiceModel = this.getTenantInvoiceModel(databaseName);
    const invoice = await invoiceModel.findById(invoiceId).exec();
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
    databaseName: string,
    dto: UpdateInvoiceDto,
    userId: string
  ): Promise<InvoiceResponseDto> {
    const invoiceModel = this.getTenantInvoiceModel(databaseName);
    const invoice = await invoiceModel.findById(invoiceId).exec();

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
    const auditUserId = this.normalizeAuditUserId(userId);
    if (auditUserId) {
      invoice.lastModifiedBy = auditUserId;
    }

    await invoice.save();

    this.logger.debug(
      `Updated draft invoice ${invoiceId} for business ${businessId}`
    );

    // Sync updated invoice to platform database
    try {
      await this.saveToPlatformDatabase(invoice, databaseName);
    } catch (error) {
      // Non-blocking: log but don't fail the update
      this.logger.warn(
        `Failed to sync updated invoice to platform database: ${error}`,
        error
      );
    }

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
    const invoiceModel = this.getTenantInvoiceModel(databaseName);
    const invoice = await invoiceModel.findById(invoiceId).exec();

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.issuerBusinessId.toString() !== businessId) {
      throw new ForbiddenException('You do not own this invoice');
    }

    // Normalize statuses so legacy lowercase/mixed-case values still follow state machine rules.
    const currentStatus = this.normalizeInvoiceStatus(invoice.status);
    const targetStatus = this.normalizeInvoiceStatus(dto.newStatus);

    // Validate state transition using state machine
    const validTransitions = INVOICE_STATUS_TRANSITIONS[currentStatus];
    if (!validTransitions.includes(targetStatus)) {
      throw new BadRequestException(
        `Cannot transition from ${currentStatus} to ${targetStatus}`
      );
    }

    // Update payment if transitioning to PAID/PARTIAL
    if (
      targetStatus === InvoiceStatus.PAID ||
      targetStatus === InvoiceStatus.PARTIAL
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
    const previousStatus = currentStatus;
    invoice.status = targetStatus;
    invoice.lastStatusChangeAt = new Date();
    const auditUserId = this.normalizeAuditUserId(userId);
    if (auditUserId) {
      invoice.lastModifiedBy = auditUserId;
    }

    // Handle voiding
    if (targetStatus === InvoiceStatus.VOIDED) {
      invoice.voidReason = dto.reason;
      invoice.voidedAt = new Date();

      // Best effort: restore reserved inventory when an invoice is voided.
      try {
        await this.restoreReservedInventoryForInvoice(invoice, databaseName);
      } catch (error) {
        this.logger.warn(
          `Failed to restore reserved inventory for voided invoice ${invoiceId}`,
          error
        );
      }
    }

    await invoice.save();

    this.logger.log(
      `Invoice ${invoiceId} transitioned from ${previousStatus} to ${targetStatus}`
    );

    // Sync invoice state change to platform database
    try {
      await this.saveToPlatformDatabase(invoice, databaseName);
    } catch (error) {
      // Non-blocking: log but don't fail the transition
      this.logger.warn(
        `Failed to sync invoice state change to platform database: ${error}`,
        error
      );
    }

    // Keep recipient-facing receipt in sync for every non-draft state.
    // ISSUED creates visibility, later transitions (VIEWED/PAID/etc.) update status for recipients.
    if (targetStatus !== InvoiceStatus.DRAFT) {
      await this.syncInvoiceToReceipt(invoice, databaseName);
    }

    if (targetStatus === InvoiceStatus.ISSUED && invoice.recipient.email) {
      try {
        const business = await this.businessModel.findById(businessId).exec();
        const issuerBusinessName = business?.name ?? 'Unknown Business';

        await this.notificationsService.createNotification({
          type: NotificationType.INVOICE_CREATED,
          message: `New invoice ${invoice.invoiceNumber} from ${issuerBusinessName}`,
          targetUserEmail: invoice.recipient.email,
          payload: {
            invoiceId: invoice._id.toString(),
            invoiceNumber: invoice.invoiceNumber,
            issuerBusinessId: businessId,
            issuerBusinessName,
            totalAmount: invoice.totalAmount,
            currency: invoice.currency,
            dueDate: invoice.dueDate,
          },
        });
      } catch (error) {
        this.logger.warn(
          `Failed to notify recipient for issued invoice ${invoiceId}`,
          error
        );
      }
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
        receiptData.recipientViewed = existingReceipt.recipientViewed;
        await this.invoiceReceiptModel.updateOne(
          { _id: existingReceipt._id },
          receiptData
        );
        this.logger.debug(
          `Updated InvoiceReceipt ${existingReceipt._id.toString()}`
        );
      } else {
        receiptData.recipientViewed = false;
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
   * Save invoice to platform database for cross-tenant visibility and archival
   * This creates or updates an invoice record in the shared Accountia database
   * Non-blocking operation - failures don't affect tenant database state
   */
  private async saveToPlatformDatabase(
    invoice: Invoice,
    tenantDatabaseName: string
  ): Promise<void> {
    try {
      // Get platform database connection
      const platformDb = this.connection.db;
      if (!platformDb) {
        this.logger.warn('Platform database not available');
        return;
      }

      // Get the invoice collection from platform database
      const platformInvoicesCollection = platformDb.collection('invoices');

      // Draft and other pre-issuance states should remain private in shared storage.
      const invoiceDataForPlatform = {
        _id: invoice._id, // Use same ID for referential integrity
        issuerBusinessId: invoice.issuerBusinessId,
        tenantDatabaseName, // Store which tenant database owns this
        invoiceNumber: invoice.invoiceNumber,
        status: invoice.status,
        createdAt: invoice.createdAt,
        updatedAt: invoice.updatedAt,
        syncedAt: new Date(), // Track when synced
      };

      if (invoice.status !== InvoiceStatus.DRAFT) {
        Object.assign(invoiceDataForPlatform, {
          recipient: invoice.recipient,
          totalAmount: invoice.totalAmount,
          currency: invoice.currency,
          amountPaid: invoice.amountPaid,
          issuedDate: invoice.issuedDate,
          dueDate: invoice.dueDate,
          lineItems: invoice.lineItems,
          description: invoice.description,
          paymentTerms: invoice.paymentTerms,
          voidReason: invoice.voidReason,
          voidedAt: invoice.voidedAt,
          createdBy: invoice.createdBy,
          lastModifiedBy: invoice.lastModifiedBy,
          lastStatusChangeAt: invoice.lastStatusChangeAt,
        });
      }

      // Upsert to handle concurrent creates/updates
      await platformInvoicesCollection.updateOne(
        { _id: invoice._id },
        { $set: invoiceDataForPlatform },
        { upsert: true }
      );
    } catch (error) {
      // Non-blocking: don't throw, just log
      // Eventual consistency: will retry on next state change or scheduled sync
      this.logger.warn(
        `Failed to save invoice ${invoice._id.toString()} to platform database`,
        error
      );
    }
  }

  private async restoreReservedInventoryForInvoice(
    invoice: Invoice,
    databaseName: string
  ): Promise<void> {
    if (!Array.isArray(invoice.lineItems) || invoice.lineItems.length === 0) {
      return;
    }

    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    const productsCollection = tenantDb.collection('products');

    for (const item of invoice.lineItems) {
      const rawProductId = this.normalizeOptionalString(String(item.productId));
      if (!rawProductId || !ObjectId.isValid(rawProductId)) {
        continue;
      }

      const quantityToRestore = Math.max(0, Number(item.quantity) || 0);
      if (quantityToRestore === 0) {
        continue;
      }

      await productsCollection.updateOne(
        { _id: new ObjectId(rawProductId) },
        { $inc: { quantity: quantityToRestore } }
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
