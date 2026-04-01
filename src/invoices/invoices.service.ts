import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  Invoice,
  InvoiceDocument,
  InvoiceStatus,
  InvoiceItem,
} from '@/business/schemas/invoice.schema';
import { CreateInvoiceDto, InvoiceStatusDto } from './dto/create-invoice.dto';
import { UpdateInvoiceDto } from './dto/update-invoice.dto';
import { InvoiceResponseDto } from './dto/invoice-response.dto';
import * as crypto from 'node:crypto';
import { EmailService } from '@/email/email.service';
import { BusinessService } from '@/business/business.service';
import { NotificationsService } from '@/notifications/notifications.service';
import { NotificationType } from '@/notifications/schemas/notification.schema';
import { Cron, CronExpression } from '@nestjs/schedule';

@Injectable()
export class InvoicesService {
  constructor(
    @InjectModel(Invoice.name) private invoiceModel: Model<InvoiceDocument>,
    private emailService: EmailService,
    @Inject(forwardRef(() => BusinessService))
    private businessService: BusinessService,
    private notificationsService: NotificationsService
  ) {}

  /**
   * Génère un numéro de facture unique
   */
  private generateInvoiceNumber(): string {
    const randomPart = crypto.randomBytes(2).toString('hex').toUpperCase();
    const timestamp = Date.now().toString(36).toUpperCase();
    return `INV-${randomPart}-${timestamp}`;
  }

  /**
   * Calcule les totaux et les taxes
   */
  private calculateTotals(
    lineItems: InvoiceItem[],
    taxRate: number
  ): { subtotal: number; taxAmount: number; total: number } {
    const subtotal = lineItems.reduce((sum, item) => sum + item.total, 0);
    const taxAmount = Math.round(((subtotal * taxRate) / 100) * 100) / 100;
    const total = subtotal + taxAmount;

    return { subtotal, taxAmount, total };
  }

  /**
   * Crée une facture
   */
  async createInvoice(
    businessOwnerId: string,
    createInvoiceDto: CreateInvoiceDto
  ): Promise<InvoiceResponseDto> {
    console.log(
      '[InvoicesService.createInvoice] Creating invoice for businessOwnerId:',
      businessOwnerId
    );

    // Validation: vérifier que dueDate > issueDate
    if (
      new Date(createInvoiceDto.dueDate) <= new Date(createInvoiceDto.issueDate)
    ) {
      throw new BadRequestException('Due date must be after issue date');
    }

    // Validation: au moins 1 article de ligne
    if (
      !createInvoiceDto.lineItems ||
      createInvoiceDto.lineItems.length === 0
    ) {
      throw new BadRequestException('Invoice must have at least one line item');
    }

    // Créer les articles de ligne avec IDs uniques
    const lineItems: InvoiceItem[] = createInvoiceDto.lineItems.map((item) => ({
      id: crypto.randomUUID(),
      description: item.description,
      quantity: item.quantity,
      unitPrice: item.unitPrice,
      total: Math.round(item.quantity * item.unitPrice * 100) / 100,
    }));

    // Calculer les totaux
    const { subtotal, taxAmount, total } = this.calculateTotals(
      lineItems,
      createInvoiceDto.taxRate || 19
    );

    // Créer la facture
    const invoiceNumber = this.generateInvoiceNumber();
    const invoice = new this.invoiceModel({
      invoiceNumber,
      businessOwnerId,
      clientName: createInvoiceDto.clientName,
      clientEmail: createInvoiceDto.clientEmail,
      clientPhone: createInvoiceDto.clientPhone,
      lineItems,
      subtotal,
      taxRate: createInvoiceDto.taxRate || 19,
      taxAmount,
      total,
      issueDate: new Date(createInvoiceDto.issueDate),
      dueDate: new Date(createInvoiceDto.dueDate),
      status: createInvoiceDto.status ?? InvoiceStatus.DRAFT,
      notes: createInvoiceDto.notes,
      currency: createInvoiceDto.currency ?? 'TND',
    });

    console.log('[InvoicesService.createInvoice] Invoice object created:', {
      invoiceNumber,
      businessOwnerId,
      clientName: createInvoiceDto.clientName,
    });

    try {
      await invoice.save();
      console.log(
        '[InvoicesService.createInvoice] ✅ Invoice saved to DB:',
        invoice._id
      );

      // If status is not DRAFT, trigger email notification immediately
      if (invoice.status !== InvoiceStatus.DRAFT) {
        invoice.sentAt = new Date();
        await invoice.save();

        const business = await this.businessService
          .findOne(businessOwnerId)
          .catch((): undefined => undefined);
        const businessName = business?.name ?? 'Accountia Professional';

        this.emailService
          .sendInvoiceNotification(
            invoice.clientEmail,
            invoice.invoiceNumber,
            invoice.total,
            invoice.currency ?? 'TND',
            invoice.dueDate,
            businessName
          )
          .catch((error) =>
            console.error(
              'Failed to send invoice notification on create:',
              error
            )
          );

        // Also send confirmation to BO
        this.emailService
          .sendInvoiceSentConfirmation(
            businessOwnerId,
            invoice.invoiceNumber,
            invoice.clientName,
            invoice.clientEmail,
            invoice.total,
            invoice.currency ?? 'TND'
          )
          .catch((error) =>
            console.error('Failed to send BO confirmation on create:', error)
          );
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      console.error(
        '[InvoicesService.createInvoice] ❌ Error saving invoice:',
        message
      );
      if (error instanceof Error && 'code' in error && error.code === 11_000) {
        throw new ConflictException('Invoice number already exists');
      }
      throw error;
    }

    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Récupère une facture par ID
   */
  async getInvoiceById(
    id: string,
    businessOwnerId: string
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(id);

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    // Vérifier que la facture appartient au business owner
    if (invoice.businessOwnerId.toString() !== businessOwnerId) {
      throw new ForbiddenException('You do not have access to this invoice');
    }

    // Ne pas retourner les factures supprimées
    if (invoice.deletedAt) {
      throw new NotFoundException('Invoice not found');
    }

    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Récupère toutes les factures d'un business owner
   */
  async getInvoicesByBusinessId(
    businessOwnerId: string,
    status?: InvoiceStatus,
    page = 1,
    limit = 10
  ): Promise<{
    invoices: InvoiceResponseDto[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    const query = {
      businessOwnerId,
      $or: [{ deletedAt: { $exists: false } }, { deletedAt: undefined }],
      ...(status && { status }),
    };

    const total = await this.invoiceModel.countDocuments(query);

    const invoices = await this.invoiceModel
      .find({ ...query })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    // Note: Do NOT update invoice status in GET request
    // Status updates should be handled by a separate cron job only
    // This prevents race conditions and side effects on read operations

    return {
      invoices: invoices.map((inv) => this.formatInvoiceResponse(inv)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Récupère les invoices pour un client MANAGÉ par email
   * Les clients créés par un BO via "Onboard New Client"
   * voient leurs invoices via /managed/invoices
   */
  async getInvoicesByClientEmail(
    clientEmail: string,
    status?: InvoiceStatus,
    page = 1,
    limit = 10
  ): Promise<{
    invoices: InvoiceResponseDto[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    const query = {
      clientEmail,
      $or: [{ deletedAt: { $exists: false } }, { deletedAt: undefined }],
      ...(status && { status }),
    };

    const total = await this.invoiceModel.countDocuments(query);
    const invoices = await this.invoiceModel
      .find({ ...query })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    return {
      invoices: invoices.map((inv) => this.formatInvoiceResponse(inv)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Récupère une facture unique par son ID si elle appartient au client
   */
  async getInvoiceByClientEmailAndId(
    id: string,
    clientEmail: string
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findOne({
      _id: id,
      clientEmail: clientEmail, // Use exact match instead of unsafe regex
      $or: [{ deletedAt: { $exists: false } }, { deletedAt: undefined }],
    });

    if (!invoice) {
      throw new NotFoundException('Invoice not found or unauthorized');
    }

    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Met à jour une facture
   */
  async updateInvoice(
    id: string,
    businessOwnerId: string,
    updateInvoiceDto: UpdateInvoiceDto
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(id);

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.businessOwnerId.toString() !== businessOwnerId) {
      throw new ForbiddenException('You do not have access to this invoice');
    }

    // Seules les factures DRAFT peuvent être modifiées
    if (invoice.status !== InvoiceStatus.DRAFT) {
      throw new BadRequestException('Only draft invoices can be modified');
    }

    // Mettre à jour les champs
    if (updateInvoiceDto.clientName) {
      invoice.clientName = updateInvoiceDto.clientName;
    }
    if (updateInvoiceDto.clientEmail) {
      invoice.clientEmail = updateInvoiceDto.clientEmail;
    }
    if (updateInvoiceDto.clientPhone) {
      invoice.clientPhone = updateInvoiceDto.clientPhone;
    }
    if (updateInvoiceDto.lineItems) {
      invoice.lineItems = updateInvoiceDto.lineItems.map((item) => ({
        id: crypto.randomUUID(),
        description: item.description,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        total: Math.round(item.quantity * item.unitPrice * 100) / 100,
      }));
    }
    if (updateInvoiceDto.issueDate) {
      invoice.issueDate = new Date(updateInvoiceDto.issueDate);
    }
    if (updateInvoiceDto.dueDate) {
      invoice.dueDate = new Date(updateInvoiceDto.dueDate);
    }

    // Validation: dueDate > issueDate
    if (new Date(invoice.dueDate) <= new Date(invoice.issueDate)) {
      throw new BadRequestException('Due date must be after issue date');
    }

    if (updateInvoiceDto.taxRate !== undefined) {
      invoice.taxRate = updateInvoiceDto.taxRate;
    }
    if (updateInvoiceDto.notes !== undefined) {
      invoice.notes = updateInvoiceDto.notes;
    }
    if (updateInvoiceDto.currency) {
      invoice.currency = updateInvoiceDto.currency;
    }

    // Recalculer les totaux
    const { subtotal, taxAmount, total } = this.calculateTotals(
      invoice.lineItems,
      invoice.taxRate
    );
    invoice.subtotal = subtotal;
    invoice.taxAmount = taxAmount;
    invoice.total = total;

    await invoice.save();
    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Supprime une facture (soft delete)
   */
  async deleteInvoice(id: string, businessOwnerId: string): Promise<void> {
    const invoice = await this.invoiceModel.findById(id);

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.businessOwnerId.toString() !== businessOwnerId) {
      throw new ForbiddenException('You do not have access to this invoice');
    }

    // Seules les factures DRAFT peuvent être supprimées
    if (invoice.status !== InvoiceStatus.DRAFT) {
      throw new BadRequestException('Only draft invoices can be deleted');
    }

    invoice.deletedAt = new Date();
    await invoice.save();
  }

  /**
   * Envoie une facture (change le statut à SENT)
   */
  async sendInvoice(
    id: string,
    businessOwnerId: string,
    customMessage?: string
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(id);

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.businessOwnerId.toString() !== businessOwnerId) {
      throw new ForbiddenException('You do not have access to this invoice');
    }

    if (invoice.status !== InvoiceStatus.DRAFT) {
      throw new BadRequestException('Only draft invoices can be sent');
    }

    invoice.status = InvoiceStatus.SENT;
    invoice.sentAt = new Date();
    await invoice.save();

    // Trigger Email Notification to client (non-blocking)
    const business = await this.businessService
      .findOne(businessOwnerId)
      .catch((): undefined => undefined);
    const businessName = business?.name ?? 'Accountia Professional';

    this.emailService
      .sendInvoiceNotification(
        invoice.clientEmail,
        invoice.invoiceNumber,
        invoice.total,
        invoice.currency || 'USD',
        invoice.dueDate,
        businessName,
        customMessage
      )
      .catch((error) =>
        console.error('Failed to send invoice notification email:', error)
      );
    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Marquer la facture comme payée (après vérification du paiement)
   */
  async markInvoiceAsPaid(
    id: string,
    clientEmail: string,
    _paymentId?: string
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findOne({
      _id: id,
      clientEmail: clientEmail,
    });

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.status === InvoiceStatus.PAID) {
      return this.formatInvoiceResponse(invoice); // Déjà payée
    }

    invoice.status = InvoiceStatus.PAID;
    invoice.paidAt = new Date();
    // On pourrait stocker le paymentId ici si le schéma l'autorise, mais pour l'instant on met juste à jour le statut
    await invoice.save();

    // Trigger Email Notification for payment success (non-blocking)
    const business = await this.businessService
      .findOne(invoice.businessOwnerId.toString())
      .catch((): undefined => undefined);
    const businessName = business?.name ?? 'Accountia Professional';

    this.emailService
      .sendInvoiceNotification(
        invoice.clientEmail,
        invoice.invoiceNumber,
        invoice.total,
        invoice.currency || 'USD',
        invoice.dueDate, // Pas grave si c'est la date d'échéance, idéalement c'est la date de paiement
        businessName,
        `Your payment of ${invoice.total.toFixed(2)} ${invoice.currency || 'USD'} has been successfully processed via Flouci. Thank you!`
      )
      .catch((error) =>
        console.error('Failed to send payment success email:', error)
      );

    // Notify Business Owner in-app
    this.notificationsService
      .createNotification({
        type: NotificationType.INVOICE_PAID,
        message: `Invoice ${invoice.invoiceNumber} has been paid by ${invoice.clientName}`,
        targetBusinessId: invoice.businessOwnerId.toString(),
        payload: {
          invoiceId: invoice._id.toString(),
          amount: invoice.total,
        },
      })
      .catch((error) =>
        console.error('Failed to send in-app notification:', error)
      );

    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Marquer la facture comme payée manuellement par le Business Owner
   */
  async markInvoiceAsPaidManual(
    id: string,
    businessOwnerId: string
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(id);

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.businessOwnerId.toString() !== businessOwnerId) {
      throw new ForbiddenException('You do not have access to this invoice');
    }

    if (invoice.status === InvoiceStatus.PAID) {
      return this.formatInvoiceResponse(invoice);
    }

    invoice.status = InvoiceStatus.PAID;
    invoice.paidAt = new Date();
    await invoice.save();

    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Active ou désactive les rappels pour une facture spécifique
   */
  async toggleInvoiceReminders(
    id: string,
    businessOwnerId: string,
    muted: boolean
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(id);

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.businessOwnerId.toString() !== businessOwnerId) {
      throw new ForbiddenException('You do not have access to this invoice');
    }

    invoice.remindersMuted = muted;
    await invoice.save();

    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Envoie manuellement un rappel de paiement
   */
  async sendManualReminder(
    id: string,
    businessOwnerId: string
  ): Promise<InvoiceResponseDto> {
    const invoice = await this.invoiceModel.findById(id);

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    if (invoice.businessOwnerId.toString() !== businessOwnerId) {
      throw new ForbiddenException('You do not have access to this invoice');
    }

    // Autorisé pour SENT, PENDING, OVERDUE
    const notAllowedStatuses = [InvoiceStatus.DRAFT, InvoiceStatus.PAID];
    if (notAllowedStatuses.includes(invoice.status)) {
      throw new BadRequestException(
        'Can only remind for sent, pending or overdue invoices'
      );
    }

    const business = await this.businessService
      .findOne(businessOwnerId)
      .catch((): undefined => undefined);
    const businessName = business?.name ?? 'Accountia Professional';

    // 1. Send Email
    await this.emailService
      .sendInvoiceReminderEmail(
        invoice.clientEmail,
        invoice.clientName,
        businessName,
        invoice.invoiceNumber,
        `${invoice.total.toFixed(2)} ${invoice.currency}`,
        invoice.dueDate.toLocaleDateString(),
        0 // 0 means manual reminder
      )
      .catch((error) =>
        console.error('Failed to send manual reminder email:', error)
      );

    // 2. Create In-App Notification for Client
    await this.notificationsService
      .createNotification({
        type: NotificationType.INVOICE_REMINDED,
        message: `Reminder: Invoice ${invoice.invoiceNumber} from ${businessName} is awaiting payment.`,
        targetUserEmail: invoice.clientEmail,
        payload: {
          invoiceId: invoice._id.toString(),
          businessName,
          amount: invoice.total,
        },
      })
      .catch((error) =>
        console.error('Failed to create in-app notification for client:', error)
      );

    // 3. Record in history
    if (!invoice.reminderHistory) invoice.reminderHistory = [];
    invoice.reminderHistory.push({
      sentAt: new Date(),
      intervalDays: 0, // Manual
    });
    await invoice.save();

    return this.formatInvoiceResponse(invoice);
  }

  /**
   * Cron Job to automatically mark invoices as OVERDUE and send reminders
   * Runs every day at midnight.
   */
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleOverdueInvoices() {
    console.log('[Cron Job] Starting daily overdue invoice check...');
    const now = new Date();

    // 1. Sync Status: Mark PENDING/SENT invoices as OVERDUE if dueDate is passed
    const justOverdueInvoices = await this.invoiceModel.find({
      status: { $in: [InvoiceStatus.PENDING, InvoiceStatus.SENT] },
      dueDate: { $lt: now },
      $or: [{ deletedAt: { $exists: false } }, { deletedAt: undefined }],
    });

    for (const invoice of justOverdueInvoices) {
      invoice.status = InvoiceStatus.OVERDUE;
      await invoice.save();

      // Notify owner in-app
      this.notificationsService
        .createNotification({
          type: NotificationType.INVOICE_OVERDUE,
          message: `Status: Invoice ${invoice.invoiceNumber} for ${invoice.clientName} is now OVERDUE.`,
          targetBusinessId: invoice.businessOwnerId.toString(),
          payload: {
            invoiceId: invoice._id.toString(),
            dueDate: invoice.dueDate,
          },
        })
        .catch((error) =>
          console.log('Error creating alert notification', error)
        );
    }

    // 2. Automated Reminders: Check all OVERDUE invoices for 5, 10, 20 day intervals
    const overdueInvoices = await this.invoiceModel.find({
      status: InvoiceStatus.OVERDUE,
      remindersMuted: { $ne: true },
      $or: [{ deletedAt: { $exists: false } }, { deletedAt: undefined }],
    });

    for (const invoice of overdueInvoices) {
      const business = await this.businessService
        .findOne(invoice.businessOwnerId.toString())
        .catch((): undefined => undefined);

      // Skip if business exists but reminders are explicitly disabled
      if (business?.automationSettings?.remindersEnabled === false) continue;

      const diffTime = Math.abs(
        now.getTime() - new Date(invoice.dueDate).getTime()
      );
      const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

      // Professional intervals: 5, 10, 20
      const targetIntervals = [5, 10, 20];
      const intervalToRemind = targetIntervals.find((i) => diffDays >= i);

      if (intervalToRemind) {
        // Check if reminder was already sent for this specific interval
        const alreadySent = invoice.reminderHistory?.some(
          (h) => h.intervalDays === intervalToRemind
        );

        if (!alreadySent) {
          console.log(
            `[Cron Job] Sending ${intervalToRemind}-day reminder for invoice ${invoice.invoiceNumber}`
          );

          await this.emailService
            .sendInvoiceReminderEmail(
              invoice.clientEmail,
              invoice.clientName,
              business?.name ?? 'Accountia Business',
              invoice.invoiceNumber,
              `${invoice.total.toFixed(2)} ${invoice.currency}`,
              invoice.dueDate.toLocaleDateString(),
              intervalToRemind
            )
            .catch((error) =>
              console.error(
                `Failed to send ${intervalToRemind}-day reminder:`,
                error
              )
            );

          // Record history
          if (!invoice.reminderHistory) invoice.reminderHistory = [];
          invoice.reminderHistory.push({
            sentAt: new Date(),
            intervalDays: intervalToRemind,
          });
          await invoice.save();
        }
      }
    }

    console.log('[Cron Job] Daily overdue invoice check completed.');
  }

  /**
   * Formate la réponse d'une facture
   */
  private formatInvoiceResponse(invoice: InvoiceDocument): InvoiceResponseDto {
    return {
      id: invoice._id.toString(),
      invoiceNumber: invoice.invoiceNumber,
      businessOwnerId: invoice.businessOwnerId.toString(),
      clientName: invoice.clientName,
      clientEmail: invoice.clientEmail,
      clientPhone: invoice.clientPhone,
      lineItems: invoice.lineItems.map((item) => ({
        id: item.id,
        description: item.description,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        total: item.total,
      })),
      subtotal: invoice.subtotal,
      taxRate: invoice.taxRate,
      taxAmount: invoice.taxAmount,
      total: invoice.total,
      issueDate: invoice.issueDate,
      dueDate: invoice.dueDate,
      status: invoice.status as unknown as InvoiceStatusDto,
      notes: invoice.notes,
      currency: invoice.currency,
      sentAt: invoice.sentAt,
      paidAt: invoice.paidAt,
      remindersMuted: invoice.remindersMuted,
      reminderHistory: invoice.reminderHistory
        ? invoice.reminderHistory.map((h) => ({
            sentAt: h.sentAt,
            intervalDays: h.intervalDays,
          }))
        : [],
      createdAt: invoice.createdAt ?? new Date(),
      updatedAt: invoice.updatedAt ?? new Date(),
    };
  }
}
