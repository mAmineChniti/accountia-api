import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { randomUUID } from 'node:crypto';
import { Invoice, InvoiceDocument, InvoiceStatus } from './schemas/invoice.schema';
import { CreateInvoiceDto, InvoicesListResponseDto, InvoiceResponseDto } from './dto/invoice.dto';
import { Role } from '@/users/schemas/user.schema';

@Injectable()
export class InvoicesService {
  constructor(
    @InjectModel(Invoice.name) private invoiceModel: Model<InvoiceDocument>
  ) {}

  // ─── Helper ────────────────────────────────────────────────────────────────

  private toDto(invoice: InvoiceDocument): InvoiceResponseDto {
    return {
      id: invoice._id.toString(),
      invoiceNumber: invoice.invoiceNumber,
      description: invoice.description,
      amount: invoice.amount,
      currency: invoice.currency,
      status: invoice.status,
      dueDate: invoice.dueDate.toISOString(),
      paidAt: invoice.paidAt?.toISOString(),
      notes: invoice.notes,
      clientId: invoice.clientId.toString(),
      businessOwnerId: invoice.businessOwnerId.toString(),
      createdAt: invoice.createdAt.toISOString(),
    };
  }

  private generateInvoiceNumber(): string {
    const year = new Date().getFullYear();
    const short = randomUUID().split('-')[0].toUpperCase();
    return `INV-${year}-${short}`;
  }

  // ─── CLIENT: récupérer ses propres factures ─────────────────────────────

  async getMyInvoices(clientId: string): Promise<InvoicesListResponseDto> {
    const invoices = await this.invoiceModel
      .find({ clientId: new Types.ObjectId(clientId) })
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'Invoices retrieved successfully',
      invoices: invoices.map((inv) => this.toDto(inv as InvoiceDocument)),
      total: invoices.length,
    };
  }

  // ─── CLIENT: récupérer une facture spécifique ───────────────────────────

  async getMyInvoiceById(clientId: string, invoiceId: string): Promise<InvoiceResponseDto> {
    if (!Types.ObjectId.isValid(invoiceId)) {
      throw new BadRequestException('Invalid invoice ID');
    }

    const invoice = await this.invoiceModel.findOne({
      _id: new Types.ObjectId(invoiceId),
      clientId: new Types.ObjectId(clientId),
    });

    if (!invoice) {
      throw new NotFoundException('Invoice not found');
    }

    return this.toDto(invoice);
  }

  // ─── BUSINESS_OWNER: créer une facture pour un client ──────────────────

  async createInvoice(
    businessOwnerId: string,
    dto: CreateInvoiceDto
  ): Promise<InvoiceResponseDto> {
    if (!Types.ObjectId.isValid(dto.clientId)) {
      throw new BadRequestException('Invalid client ID');
    }

    const invoice = new this.invoiceModel({
      clientId: new Types.ObjectId(dto.clientId),
      businessOwnerId: new Types.ObjectId(businessOwnerId),
      invoiceNumber: this.generateInvoiceNumber(),
      description: dto.description,
      amount: dto.amount,
      currency: dto.currency ?? 'USD',
      dueDate: new Date(dto.dueDate),
      notes: dto.notes,
      status: InvoiceStatus.PENDING,
    });

    await invoice.save();
    return this.toDto(invoice);
  }

  // ─── BUSINESS_OWNER: voir ses factures émises ──────────────────────────

  async getMyIssuedInvoices(businessOwnerId: string): Promise<InvoicesListResponseDto> {
    const invoices = await this.invoiceModel
      .find({ businessOwnerId: new Types.ObjectId(businessOwnerId) })
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'Invoices retrieved successfully',
      invoices: invoices.map((inv) => this.toDto(inv as InvoiceDocument)),
      total: invoices.length,
    };
  }

  // ─── BUSINESS_OWNER: mettre à jour le statut ───────────────────────────

  async updateInvoiceStatus(
    businessOwnerId: string,
    invoiceId: string,
    status: InvoiceStatus
  ): Promise<InvoiceResponseDto> {
    if (!Types.ObjectId.isValid(invoiceId)) {
      throw new BadRequestException('Invalid invoice ID');
    }

    const invoice = await this.invoiceModel.findOne({
      _id: new Types.ObjectId(invoiceId),
      businessOwnerId: new Types.ObjectId(businessOwnerId),
    });

    if (!invoice) {
      throw new NotFoundException('Invoice not found or not owned by you');
    }

    invoice.status = status;
    if (status === InvoiceStatus.PAID) {
      invoice.paidAt = new Date();
    }

    await invoice.save();
    return this.toDto(invoice);
  }

  // ─── BUSINESS_OWNER: supprimer une facture ─────────────────────────────

  async deleteInvoice(businessOwnerId: string, invoiceId: string): Promise<void> {
    if (!Types.ObjectId.isValid(invoiceId)) {
      throw new BadRequestException('Invalid invoice ID');
    }

    const result = await this.invoiceModel.deleteOne({
      _id: new Types.ObjectId(invoiceId),
      businessOwnerId: new Types.ObjectId(businessOwnerId),
    });

    if (result.deletedCount === 0) {
      throw new NotFoundException('Invoice not found or not owned by you');
    }
  }

  // ─── ADMIN: toutes les factures ────────────────────────────────────────

  async getAllInvoices(): Promise<InvoicesListResponseDto> {
    const invoices = await this.invoiceModel
      .find()
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'All invoices retrieved successfully',
      invoices: invoices.map((inv) => this.toDto(inv as InvoiceDocument)),
      total: invoices.length,
    };
  }
}